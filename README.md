# Vault storage module for Caddy
Uses [Vault](https://vaultproject.io/) as a storage backend for [Caddy](https://caddyserver.com/). This module supports to configure multiple Vault servers to ensure high availability. If a request on one configured address failes, another will be tried.

## Notice
A running Vault instance/cluster with an enabled KVv2 mount is required for using this plugin.

## Usage
To build caddy with this module run `xcaddy build --with github.com/gerolf-vent/caddy-vault-storage`.

### Configuration
This module is based on the [Vault api client](https://pkg.go.dev/github.com/hashicorp/vault/api), so it supports most of it's [environment variables](https://developer.hashicorp.com/vault/docs/commands#environment-variables). The environment variables `VAULT_ADDR` and `VAULT_MAX_RETRIES` are ignored. **For authentication, use the `VAULT_TOKEN` environment variable.**

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| addresses | string | *None* | One or more addresses of Vault servers (on the **same** cluster) separated by `,` |
| secrets_mount_path | string | `"kv"` | Path of the KVv2 mount to use |
| secrets_path_prefix | string | `"caddy"` | Path in the KVv2 mount to use |
| max_retries | int | `3` | Limit of connection retries after which to fail a request |
| lock_timeout | int | `60` | Timeout for locks (in seconds) |
| lock_check_interval | int | `5` | Interval for checking lock status (in seconds) |

### Example
Run `VAULT_TOKEN="..." caddy run --config server.json` with the following configuration as `server.json`:
```json
{
	"storage": {
		"module": "vault",
		"addresses": ["https://server1", "https://server2", "https://server3"]
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

## Testing
A running vault instance/cluster with at least two distinct addresses is required to run all of the tests. The tests can be performed by `VAULT_STORAGE_ADDR="https://server1,https://server2" VAULT_TOKEN="..." go test`. Extensive logging is enabled to debug any errors.
