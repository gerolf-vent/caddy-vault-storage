package caddy_vault_storage

import (
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

	err = s.StoreLoadDeleteCheck(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *VaultStorage) CertMagicStorage() (certmagic.Storage, error) {
	return s, nil
}
