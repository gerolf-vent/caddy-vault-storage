# A storage module for [Caddy](https://caddyserver.com/) that uses HashiCorp [Vault](https://vaultproject.io/) as backend
This module supports to configure multiple Vault servers to ensure high availability. If a request on one configured address failes, another will be tried. This is useful, if you don't have a load-balancer for your Vault cluster or you are using Caddy as a load balancer for it.

If you run Caddy inside a Nomad cluster, you can use Nomad to [issue Vault tokens for it](nomad-integration.md).

## Notice
A running Vault instance/cluster with an enabled KVv2 mount is required for using this module. At startup a check for required capabilities on the configured secrets path will be performed and error messages will be shown with the missing capabilties, if any. The following capabilities must be granted:
```hcl
path "kv/metadata/caddy/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv/data/caddy/*" {
  capabilities = ["create", "read", "update"]
}

path "kv/delete/caddy/*" {
  capabilities = ["create", "update"]
}
```
Replace `kv` with your KVv2 mount path and `caddy` with your secrets path prefix, if you are using different values than the defaults ones.

## Usage
To build caddy with this module run `xcaddy build --with github.com/gerolf-vent/caddy-vault-storage`.

### Configuration
This module is based on the [Vault api client](https://pkg.go.dev/github.com/hashicorp/vault/api), so it supports most of it's [environment variables](https://developer.hashicorp.com/vault/docs/commands#environment-variables). The environment variables `VAULT_ADDR` and `VAULT_MAX_RETRIES` are ignored.

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| addresses | []string (or comma-separated string in Caddyfile) | *None* | One or more addresses of Vault servers (on the **same** cluster) |
| token_path | string | `$VAULT_TOKEN` environment variable | Local path to read the access token from. Updates on that file will be detected and automatically read. |
| secrets_mount_path | string | `"kv"` | Path of the KVv2 mount to use |
| secrets_path_prefix | string | `"caddy"` | Path in the KVv2 mount to use |
| max_retries | int | `3` | Limit of connection retries after which to fail a request |
| lock_timeout | int | `60` | Timeout for locks (in seconds) |
| lock_check_interval | int | `5` | Interval for checking lock status (in seconds) |

### Example
Run `caddy run --config server.json` with the following configuration as `server.json`:
```json
{
	"storage": {
		"module": "vault",
		"addresses": ["https://server1", "https://server2", "https://server3"],
		"token_path": "./vault_token"
	},
	"logging": {
		"logs": {
			"default": {
				"level": "DEBUG"
			}
		}
	},
	"apps": {
		"http": {
			"servers": {
				"example": {
					"listen": [":8000"],
					"routes": [
						{
							"match": [{
								"host": ["localhost"]
							}],
							"handle": [{
								"handler": "static_response",
								"body": "Hello, world!"
							}]
						}
					]
				}
			}
		}
	}
}
```

Or `caddy run --config Caddyfile --adapter caddyfile` with the following configuration as `Caddyfile`:
```caddyfile
{
  storage vault {
    addresses "https://server1,https://server2,https://server3"
    token_path "./vault_token"
  }
  debug
}

localhost:8000

respond "Hello, world!"
```

## Testing
A running vault instance/cluster with at least two distinct addresses is required to run all of the tests. The tests can be performed by `VAULT_STORAGE_ADDR="https://server1,https://server2" VAULT_TOKEN="..." go test`. Extensive logging is enabled to debug any errors.
