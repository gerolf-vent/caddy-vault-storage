package caddy_vault_storage

import (
	"context"
	"fmt"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
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

	if s.TokenPath != "" {
		err := s.LoadTokenFromFile()
		if err != nil {
			return err
		}

		var watcher *fsnotify.Watcher
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return err
		}

		err = watcher.Add(s.TokenPath)
		if err != nil {
			return err
		}

		s.tokenFileWatcher = watcher

		go func() {
			s.logger.Debug("Started token file watcher", zap.String("path", s.TokenPath))
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						s.logger.Debug("Stopped token file watcher", zap.String("path", s.TokenPath))
						return
					}
					if event.Has(fsnotify.Write) {
						s.logger.Debug("Token file has been updated", zap.String("path", s.TokenPath))
						s.LoadTokenFromFile()
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						s.logger.Debug("Stopped token file watcher", zap.String("path", s.TokenPath))
						return
					}
					s.logger.Error("An error occurred while watching the token file", zap.Error(err))
				}
			}
		}()
	}

	return nil
}

func (s *VaultStorage) Validate() error {
	if len(s.Addresses) == 0 {
		return fmt.Errorf("At least one Vault server address is required")
	}

	_, tokenEnvExists := os.LookupEnv("VAULT_TOKEN")
	if !tokenEnvExists && s.TokenPath == "" {
		return fmt.Errorf("A token path or environment variable is required")
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

func (s *VaultStorage) Cleanup() error {
	if s.tokenFileWatcher != nil {
		err := s.tokenFileWatcher.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner      = (*VaultStorage)(nil)
	_ caddy.Validator        = (*VaultStorage)(nil)
	_ caddy.StorageConverter = (*VaultStorage)(nil)
	_ caddy.CleanerUpper     = (*VaultStorage)(nil)
)
