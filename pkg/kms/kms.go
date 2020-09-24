package kms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
)

// Major TODOS:
// - error embellishment and wrapping
// - logging
// - maps from spire enums to kms enums
// - input validations
// - consume kms client through an interface so we can replace it with a fake
// - kms client fake
// - testing

const keyPrefix = "SPIRE_SERVER_KEY:"

type entry struct {
	AwsKeyID     string
	CreationDate *time.Time //TODO: maybe not a pointer
	PublicKey    *keymanager.PublicKey
}

type Plugin struct {
	config    *Config
	mu        sync.RWMutex
	entries   map[string]*entry
	kmsClient *kms.KMS
}

type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
}

func New() *Plugin {
	return &Plugin{
		entries: make(map[string]*entry),
	}
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config, err := configure(req.Configuration)
	if err != nil {
		return nil, err
	}

	p.config = config
	kmsClient, err := newKMSClient(config)
	if err != nil {
		return nil, err
	}

	p.kmsClient = kmsClient

	// TODO: pagination
	listKeysResp, err := kmsClient.ListKeysWithContext(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, err
	}

	for _, key := range listKeysResp.Keys {
		err := p.processKMSKey(ctx, key.KeyId)
		if err != nil {
			return nil, err
		}

	}

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) processKMSKey(ctx context.Context, awsKeyID *string) error {
	describeResp, err := p.kmsClient.DescribeKeyWithContext(ctx, &kms.DescribeKeyInput{KeyId: awsKeyID})
	if err != nil {
		return err
	}

	if *describeResp.KeyMetadata.Enabled == true && strings.HasPrefix(*describeResp.KeyMetadata.Description, keyPrefix) {
		descSplit := strings.SplitAfter(*describeResp.KeyMetadata.Description, keyPrefix)
		spireKeyID := descSplit[1]
		getPublicKeyResp, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: awsKeyID})
		if err != nil {
			return err
		}

		e := &entry{
			AwsKeyID:     *awsKeyID,
			CreationDate: describeResp.KeyMetadata.CreationDate,
			PublicKey: &keymanager.PublicKey{
				Id: spireKeyID,
				// TODO: KeyType
				PkixData: getPublicKeyResp.PublicKey,
			},
		}
		p.setEntry(spireKeyID, e)
	}
	return nil
}

func (p *Plugin) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	spireKeyID := req.KeyId
	description := fmt.Sprintf("%v%v", keyPrefix, spireKeyID)

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description), //TODO: check using alias instead
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecEccNistP256), //TODO: build a map from input to this
		//TODO: look into policies
	}

	key, err := p.kmsClient.CreateKeyWithContext(ctx, createKeyInput)
	if err != nil {
		return nil, err
	}

	pub, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil {
		return nil, err
	}

	newEntry := &entry{
		AwsKeyID:     *pub.KeyId,
		CreationDate: key.KeyMetadata.CreationDate,
		PublicKey: &keymanager.PublicKey{
			Id: spireKeyID,
			// TODO: KeyType
			PkixData: pub.PublicKey,
		},
	}

	oldEntry, hasOldEntry := p.entry(spireKeyID)
	ok := p.setEntry(spireKeyID, newEntry)

	// only delete if an old entry was replaced by a new one
	if hasOldEntry && ok {
		_, err := p.kmsClient.ScheduleKeyDeletionWithContext(ctx, &kms.ScheduleKeyDeletionInput{KeyId: &oldEntry.AwsKeyID})
		if err != nil {
			return nil, err
		}
	}

	return &keymanager.GenerateKeyResponse{PublicKey: newEntry.PublicKey}, nil
}

func (p *Plugin) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	keyEntry, hasKey := p.entry(req.KeyId)
	if !hasKey {
		return nil, fmt.Errorf("could not find key: %v", req.KeyId)
	}

	signResp, err := p.kmsClient.SignWithContext(ctx, &kms.SignInput{
		KeyId:            &keyEntry.AwsKeyID,
		Message:          req.Data,
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecEcdsaSha256), //TODO: this should match the they key type we are using plus the input param
	})
	if err != nil {
		return nil, err
	}

	return &keymanager.SignDataResponse{Signature: signResp.Signature}, nil
}

func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, errors.New("KeyId is required")
	}

	resp := new(keymanager.GetPublicKeyResponse)

	e, ok := p.entry(req.KeyId)
	if !ok {
		//TODO: isn't it better to return error?
		return resp, nil
	}

	//TODO: clone it
	resp.PublicKey = e.PublicKey
	return resp, nil
}

func (p *Plugin) GetPublicKeys(context.Context, *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	keys := p.publicKeys()
	return &keymanager.GetPublicKeysResponse{PublicKeys: keys}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) setEntry(spireKeyID string, newEntry *entry) bool {
	//TODO: validate new entry
	p.mu.Lock()
	defer p.mu.Unlock()
	oldEntry, hasKey := p.entries[spireKeyID]
	if hasKey && oldEntry.CreationDate.Unix() > newEntry.CreationDate.Unix() {
		//TODO: log this. Also when there is a key and it's updated
		return false
	}
	p.entries[spireKeyID] = newEntry
	return true
}

func (p *Plugin) entry(spireKeyID string) (*entry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	value, hasKey := p.entries[spireKeyID]
	return value, hasKey
}

func (p *Plugin) publicKeys() []*keymanager.PublicKey {
	var keys []*keymanager.PublicKey

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}
	return keys
}

func configure(c string) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, c); err != nil {
		return nil, fmt.Errorf("unable to decode configuration: %v", err)
	}

	// TODO: validate
	// if config.SomeValue == "" {
	// 	return nil, errors.New("some_value is required")
	// }
	return config, nil
}

func newKMSClient(c *Config) (*kms.KMS, error) {
	creds := credentials.NewStaticCredentials(c.AccessKeyID, c.SecretAccessKey, "")
	awsConf := &aws.Config{Credentials: creds, Region: aws.String(c.Region)}
	s, err := session.NewSession(awsConf)
	if err != nil {
		return nil, err
	}

	return kms.New(s), nil

}

type kmsClient interface {
	CreateKeyWithContext(aws.Context, *kms.CreateKeyInput, ...request.Option) (*kms.CreateKeyOutput, error)
	DescribeKeyWithContext(aws.Context, *kms.DescribeKeyInput, ...request.Option) (*kms.DescribeKeyOutput, error)
	GetPublicKeyWithContext(aws.Context, *kms.GetPublicKeyInput, ...request.Option) (*kms.GetPublicKeyOutput, error)
	ListKeysWithContext(aws.Context, *kms.ListKeysInput, ...request.Option) (*kms.ListKeysOutput, error)
	ScheduleKeyDeletionWithContext(aws.Context, *kms.ScheduleKeyDeletionInput, ...request.Option) (*kms.ScheduleKeyDeletionOutput, error)
	SignWithContext(aws.Context, *kms.SignInput, ...request.Option) (*kms.SignOutput, error)
}
