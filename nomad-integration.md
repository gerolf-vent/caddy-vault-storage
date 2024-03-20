# Integration with HashiCorp Nomad
This module works great in conjunction with HashiCorp [Nomad.](https://www.nomadproject.io/), because Nomad can automatically retreive and update the Vault token for you.

## 1. Setup Vault integration for Nomad

The following example uses [Workload Identities](https://developer.hashicorp.com/nomad/docs/concepts/workload-identity) for authenticating the job against Vault. The setup process for integrating Nomad with Vault is explained [here](https://developer.hashicorp.com/nomad/tutorials/integrate-vault/vault-acl). 

You should now have a working JWT authentication flow between Nomad and Vault. In the following guide the mount path of the JWT auth engine is expected to be `jwt-nomad`.

## 2. Create Vault policy
Login to Vault and create a policy with the name `caddy` and the following contents:
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
Replace `kv` with your KVv2 mount path and `caddy` with your secrets path prefix respectivly.

You can do this via the Vault CLI with the command `vault write sys/policy/caddy ./vault-policy.hcl`.

## 3. Create Vault JWT role
Adjust the `bound_audiences` and `token_period` in the following JWT role configuration according to your needs:
```json
{
  "role_type": "jwt",
  "bound_audiences": ["vault.io"],
  "user_claim": "/nomad_job_id",
  "user_claim_json_pointer": true,
  "claim_mappings": {
    "nomad_namespace": "nomad_namespace",
    "nomad_job_id": "nomad_job_id",
    "nomad_task": "nomad_task"
  },
  "token_type": "service",
  "token_policies": ["default", "caddy"],
  "token_period": "30m",
  "token_explicit_max_ttl": 0
}

```
Then create the role with `vault write auth/jwt-nomad/role/caddy '@vault-jwt-role.json'`.

## 4. Run Nomad job
For running Caddy with this storage module, you have to build it yourself and host it as a container image or raw tarball on a local file server. Then you can run a nomad job like this:
```hcl
job "web-app" {

  task "caddy" {
    driver = "exec"
    config {
      command = "local/bin/caddy"
      args = ["run", "--config", "local/config/caddy-config.json"]
      cap_add = ["net_bind_service"]
    }
    vault {
      role = "caddy"
      change_mode = "noop"
    }
    artifact {
      source = "https://local-file-server/caddy.tar.gz"
      destination = "local/bin"
      options {
        checksum = "sha256:..."
      }
    }
    artifact {
      source = "https://local-file-server/caddy-config.json"
      destination = "local/config"
      options {
        checksum = "sha256:..."
      }
    }
  }

}
```
with a caddy configuration like this:
```json
{
  "storage": {
    "module": "vault",
    "addresses": ["https://server1", "https://server2", "https://server3"],
    "token_file": "secrets/vault_token"
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
          "listen": ["0.0.0.0:80", "0.0.0.0:443", "[::]:80", "[::]:443"],
          "routes": [
            {
              "match": [{
                "host": ["example.com"]
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
