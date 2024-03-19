package caddy_vault_storage

import (
	"context"
	"fmt"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

func init() {
	caddy.RegisterModule(VaultStorage{})
}

func (VaultStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.vault",
		New: func() caddy.Module {
			return New()
		},
	}
}

func (s *VaultStorage) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()

	err := s.Connect(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *VaultStorage) Validate() error {
	if len(s.Addresses) == 0 {
		return fmt.Errorf("At least one Vault server address is required")
	}

	_, tokenEnvExists := os.LookupEnv("VAULT_TOKEN")
	if !tokenEnvExists {
		return fmt.Errorf("A token environment variable is required")
	}

	ctx := context.Background()
	err := s.StoreLoadDeleteCheck(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *VaultStorage) CertMagicStorage() (certmagic.Storage, error) {
	return s, nil
}

// Interface guards
var (
	_ caddy.Provisioner      = (*VaultStorage)(nil)
	_ caddy.Validator        = (*VaultStorage)(nil)
	_ caddy.StorageConverter = (*VaultStorage)(nil)
)
