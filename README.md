# Server plugin: KeyManager "kms"

The `kms` key manager plugin leverages the AWS Key Management Service (KMS) to create, maintain and rotate key pairs (as [Customer master keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys), or CMKs), and sign SVIDs as needed, with the private key never leaving KMS.

## Configuration

The plugin accepts the following configuration options:

| Key | Type | Required | Description |
| - | - | - | - |
| access_key_id | string | yes | The Access Key Id used to authenticate to KMS
| secret_access_key | string | yes | The Secret Access Key used to authenticate to KMS
| region | string | yes | The region where the keys will be stored

## Supported key types and TTL

The plugin creates CMKs of the same key type configured in the SPIRE Server. At the time of this writing the plugin supports all the set of keys supported by SPIRE: `rsa-2048`, `rsa-4096`, `ec-p256`, and  `ec-p384`. It defaults to `ec-p256` if not specified.

In order to configure it you can set the `ca_key_type` value in the SPIRE Server config file.

You can also set the TTL that the plugin will use to rotate the CMKs by setting the `ca_ttl` config in the same config file.

For more info refer to the [Server configuration section](https://github.com/spiffe/spire/blob/master/doc/spire_server.md#server-configuration-file) in the SPIRE Server documentation and to the [full server config file](https://github.com/spiffe/spire/blob/master/conf/server/server_full.conf) for a complete Server config example.

## Sample plugin configuration

```
KeyManager "kms" {
    plugin_cmd = "bin/kms_keymanager"
    plugin_checksum = "5c67edba8371f3ee5cc25dadf08b29281f7c747fa32de1323aba13aca60abe70"
    plugin_data {
        access_key_id = "ABIAXWLCWD9J4X873CQ2"
        secret_access_key = "CFiEHGH4N6LerdAt99SPwxmwoJ6IB1pPLJxTGoPN"
        region = "us-east-2"
    }
}
```