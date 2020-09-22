package kms

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
)

const keyPrefix = "SPIRE_SERVER_KEY:"

type entry struct {
	AwsKeyID     string
	CreationDate *time.Time //TODO: maybe not a pointer
	PublicKey    *keymanager.PublicKey
}

type Plugin struct {
	config    *Config
	mtx       sync.Mutex
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

func (k *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config, err := configure(req.Configuration)
	if err != nil {
		return nil, err
	}

	k.config = config
	kmsClient, err := newKMSClient(config)
	if err != nil {
		return nil, err
	}

	k.kmsClient = kmsClient

	// TODO: pagination
	listKeysResp, err := kmsClient.ListKeys(&kms.ListKeysInput{})
	if err != nil {
		return nil, err
	}

	for _, key := range listKeysResp.Keys {
		//TODO: extract into a function
		awsKeyID := key.KeyId
		describeResp, err := kmsClient.DescribeKey(&kms.DescribeKeyInput{KeyId: awsKeyID})
		if err != nil {
			return nil, err
		}

		switch {
		case *describeResp.KeyMetadata.Enabled == true && strings.HasPrefix(*describeResp.KeyMetadata.Description, keyPrefix):
			descSplit := strings.SplitAfter(*describeResp.KeyMetadata.Description, keyPrefix)
			spireKeyID := descSplit[1]
			getPublicKeyResp, err := kmsClient.GetPublicKey(&kms.GetPublicKeyInput{KeyId: awsKeyID})
			if err != nil {
				return nil, err
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
			k.setEntry(spireKeyID, e)
		default:
			continue
		}
	}

	return &plugin.ConfigureResponse{}, nil
}

func (k *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (k *Plugin) GenerateKey(_ context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	spireKeyID := req.KeyId
	description := fmt.Sprintf("%v%v", keyPrefix, spireKeyID)

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description), //TODO: check using alias instead
		KeyUsage:              aws.String("SIGN_VERIFY"),
		CustomerMasterKeySpec: aws.String("ECC_NIST_P256"), //TODO: build a map from input to this
		//TODO: look into policies
	}

	key, err := k.kmsClient.CreateKey(createKeyInput)
	if err != nil {
		return nil, err
	}

	pub, err := k.kmsClient.GetPublicKey(&kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
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

	oldEntry, hasOldEntry := k.entry(spireKeyID)
	ok := k.setEntry(spireKeyID, newEntry)

	// only delete if an old entry was replaced by a new one
	if hasOldEntry && ok {
		_, err := k.kmsClient.ScheduleKeyDeletion(&kms.ScheduleKeyDeletionInput{KeyId: &oldEntry.AwsKeyID})
		if err != nil {
			return nil, err
		}
	}

	return &keymanager.GenerateKeyResponse{PublicKey: newEntry.PublicKey}, nil
}

func (k *Plugin) setEntry(spireKeyID string, newEntry *entry) bool {
	//TODO: validate new entry
	k.mtx.Lock()
	defer k.mtx.Unlock()
	oldEntry, hasKey := k.entries[spireKeyID]
	if hasKey && oldEntry.CreationDate.Unix() > newEntry.CreationDate.Unix() {
		//TODO: log this. Also when there is a key and it's updated
		return false
	}
	k.entries[spireKeyID] = newEntry
	return true
}

func (k *Plugin) entry(spireKeyID string) (*entry, bool) {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	value, hasKey := k.entries[spireKeyID]
	return value, hasKey
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

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
// type Plugin interface {
// 	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
// 	GenerateKey(context.Context, *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error)
// 	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
// 	GetPublicKey(context.Context, *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error)
// 	GetPublicKeys(context.Context, *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error)
// 	SignData(context.Context, *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error)
// }
