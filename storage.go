package caddy_vault_storage

import (
	"bufio"
	"container/list"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/caddyserver/certmagic"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// A highly available storage module that integrates with HashiCorp Vault. 
type VaultStorage struct {
	client *vault.Client
	logger *zap.Logger

	// Address that caused a reconnect
	clientLastFailedAddress string

	// Lock for connection management
	connectionLock sync.RWMutex

	// Holds the local lock version information
	lockVersions sync.Map

	// Fs watcher for token file
	tokenFileWatcher *fsnotify.Watcher

	// One or more address(es) to Vault servers on the same cluster. (At least one address is required.)
	Addresses []string `json:"addresses"`

	// Local path to read the access token from. Updates on that file will be
	// detected and automatically read. (As fallback the the environment
	// variable "VAULT_TOKEN" will be used, but it will only be read once on
	// startup.)
	TokenPath string `json:"token_path,omitempty"`

	// Path of the KVv2 mount to use. (Default is "kv".)
	SecretsMountPath string `json:"secrets_mount_path,omitempty"`

	// Path in the KVv2 mount to use. (Default is "caddy".)
	SecretsPathPrefix string `json:"secrets_path_prefix,omitempty"`

	// Limit of connection retries after which to fail a request. (Default is 3.)
	MaxRetries int `json:"max_retries,omitempty"`

	// Timeout for locks (in seconds). (Default is 60.)
	LockTimeout int `json:"lock_timeout,omitempty"`

	// Interval for checking lock status (in seconds). (Default is 5.)
	LockCheckInterval int `json:"lock_check_interval,omitempty"`
}

/**
 * Data structure for lock information
 */
type LockInfo struct {
	Created time.Time
	Version int  // Version number of the current holded lock (required for check-and-set)
	IsLocked bool
}

/**
 * Errors
 */
var ErrRetriesExceeded = errors.New("Connection retry count exceeded")
var ErrAllServersUnavailable = errors.New("All servers are unavailable")
var ErrNoServersConfigured = errors.New("No servers configured")
var ErrClientNotInitialized = errors.New("Client is not initialized")
var ErrInvalidValue = errors.New("Data in this key has an invalid value")
var ErrInvalidResponse = errors.New("Couldn't process an invalid response")

/**
 * Creates a new vault storage module instance with default values
 */
func New() *VaultStorage {
	s := VaultStorage{
		Addresses: []string{},
		TokenPath: "",
		SecretsMountPath: "kv",
		SecretsPathPrefix: "caddy",
		MaxRetries: 3,
		LockTimeout: 60,
		LockCheckInterval: 5,
	}

	return &s
}

/**
 * Adds the secrets path prefix (from configuration) to the path provided.
 */
func (s *VaultStorage) PrefixPath(path string) string {
	return strings.Trim(strings.Trim(s.SecretsPathPrefix, "/") + "/" + path, "/")
}

/**
 * Loads the access token from the configured file path
 */
func (s *VaultStorage) LoadTokenFromFile() error {
	if s.TokenPath == "" {
		return nil
	}

	isReloading := s.client.Token() != ""

	tokenFile, err := os.Open(s.TokenPath)
	if err != nil {
		if isReloading {
			s.logger.Error("Failed to load loken from file", zap.String("path", s.TokenPath), zap.Error(err))
		} else {
			s.logger.Error("Failed to reload loken from file", zap.String("path", s.TokenPath), zap.Error(err))
		}
		return err
	}
	defer tokenFile.Close()

	tokenScanner := bufio.NewScanner(tokenFile)
	tokenScanner.Scan()
	token := tokenScanner.Text()

	s.connectionLock.Lock()
	s.client.SetToken(token)
	s.connectionLock.Unlock()

	if isReloading {
		s.logger.Debug("Reloaded token from file", zap.String("path", s.TokenPath))
	} else {
		s.logger.Debug("Loaded token from file", zap.String("path", s.TokenPath))
	}

	return nil
}

/**
 * Establishes a connection to a healthy Vault instance.
 * 
 * `s.client` will always be initialized and reused, if already existing, so there
 * can't be a nil dereference error, when at least calling this once.
 * 
 * If there is more than one address configured, every address will be checked
 * to be a healthy Vault instance and the first healthy instance will be used.
 */
func (s *VaultStorage) Connect(ctx context.Context) error {
	if s.clientLastFailedAddress != "" {
		s.logger.Debug("Reconnecting", zap.String("addressFailed", s.clientLastFailedAddress))
	} else {
		s.logger.Debug("Connecting")
	}

	if len(s.Addresses) == 0 {
		return ErrNoServersConfigured
	}

	for _, address := range s.Addresses {
		// If reconnecting, skip the address that caused the reconnection
		if address == s.clientLastFailedAddress && len(s.Addresses) > 1 {
			s.logger.Debug("Skipping failed address", zap.String("address", address))
			continue
		}

		if s.client == nil {
			// There is no client configured, so create it
			clientConfig := vault.DefaultConfig()
			clientConfig.Address = address
			clientConfig.MaxRetries = 1  // We handle retries our own way
			client, err := vault.NewClient(clientConfig)
			if err != nil {
				s.logger.Error("Failed to initialize Vault client", zap.String("address", address), zap.Error(err))
				continue
			}
			s.client = client
		} else {
			// Reuse the existing client
			err := s.client.SetAddress(address);
			if err != nil {
				s.logger.Error("Failed to initialize Vault client", zap.String("address", address), zap.Error(err))
				continue
			}
		}

		healthResponse, err := s.client.Sys().HealthWithContext(ctx)
		if err != nil {
			s.logger.Warn("Failed to get health status", zap.String("address", address), zap.Error(err))
			continue
		}

		if !healthResponse.Initialized {
			s.logger.Warn("Vault server is not initialized", zap.String("address", address))
			continue
		}

		if healthResponse.Sealed {
			s.logger.Warn("Vault server is sealed", zap.String("address", address))
			continue
		}

		s.logger.Info("Connected", zap.String("address", address))
		s.clientLastFailedAddress = ""  // Reset the address of failed instance, because we have a new working one now

		return nil
	}

	s.logger.Error("All addresses are unavailable")
	return ErrAllServersUnavailable
}

/**
 * Checks whether the provided token has enough access rights to perform all
 * operations, that this module requires.
 */
func (s *VaultStorage) CheckCapabilities(ctx context.Context) error {
	var err error
	metadataCheckPassed, err := s.CheckCapabilitiesOnPath(ctx, s.SecretsMountPath + "/metadata/" + s.SecretsPathPrefix + "/*", []string{"create", "read", "list", "update", "delete"})
	if err != nil {
		var responseError *vault.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == 403 {
			return fmt.Errorf("Provided token is invalid")
		} else {
			return err
		}
	}

	var dataCheckPassed bool
	dataCheckPassed, err = s.CheckCapabilitiesOnPath(ctx, s.SecretsMountPath + "/data/" + s.SecretsPathPrefix + "/*", []string{"create", "read", "update"})
	if err != nil {
		return err
	}

	var deleteCheckPassed bool
	deleteCheckPassed, err = s.CheckCapabilitiesOnPath(ctx, s.SecretsMountPath + "/delete/" + s.SecretsPathPrefix + "/*", []string{"create", "update"})
	if err != nil {
		return err
	}

	if metadataCheckPassed && dataCheckPassed && deleteCheckPassed {
		s.logger.Debug("Capabilities check passed", zap.String("address", s.client.Address()))
		return nil
	} else {
		return fmt.Errorf("Capabilities check failed")
	}
}

/**
 * Checks if a set of required capabilities are granted on a given api path
 */
func (s *VaultStorage) CheckCapabilitiesOnPath(ctx context.Context, path string, requiredCapabilities []string) (bool, error) {
	grantedCapabilities, err := s.client.Sys().CapabilitiesSelfWithContext(ctx, path)
	if err != nil {
		return false, err
	}

	var missingCapabilities []string
	for _, capability := range requiredCapabilities {
		if !slices.Contains(grantedCapabilities, capability) {
			missingCapabilities = append(missingCapabilities, capability)
		}
	}

	if len(missingCapabilities) > 0 {
		s.logger.Error("Some capabilities are missing", zap.String("address", s.client.Address()), zap.String("path", path), zap.Any("missingCapabilities", missingCapabilities))
	}

	return len(missingCapabilities) == 0, nil
}

/**
 * Checks the provieded error and decides, whether a reconnection is necessary,
 * than performs that reconnection and reports it's decision to the caller.
 */
func (s *VaultStorage) ReconnectOnError(ctx context.Context, err error, clientAddressTried string) (bool, error) {
	if s.client == nil {
		return false, ErrClientNotInitialized
	}

	reconnect := false

	// Reconnect on connectivity errors
	var urlError *url.Error
	if errors.As(err, &urlError) {
		reconnect = true
	}

	// Reconnect on server errors
	var responseError *vault.ResponseError
	if errors.As(err, &responseError) {
		if (responseError.StatusCode >= 500) {
			reconnect = true
		}
	}

	if (reconnect) {
		// If there are less than two addresses to choose from, an actual reconnect wouldn't do anything
		if len(s.Addresses) < 2 {
			s.logger.Debug("Skipping actual reconnection, because there are not enough addresses configured")
			return true, nil  // Still perform a connection retry
		}

		s.connectionLock.Lock()
		defer s.connectionLock.Unlock()

		// Check whether we already have reconnected (because some other goroutine was faster)
		if s.client.Address() == clientAddressTried {
			s.clientLastFailedAddress = clientAddressTried
			err := s.Connect(ctx)
			if err != nil {
				return false, err
			}
		} else {
			s.logger.Debug("Reconnection aborted, because client address has changed in the meantimes")
		}
	}

	return reconnect, nil
}

/**
 * Tries to create a lock or blocks until an existing lock is freed (or timed out)
 * and then tries to create the lock again.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Locker
 */
func (s *VaultStorage) Lock(ctx context.Context, path string) error {
	path = strings.Trim(path, "/")

	s.logger.Debug("Locking", zap.String("path", path))

	if s.client == nil {
		s.logger.Debug("Locking failed", zap.String("path", path), zap.Error(ErrClientNotInitialized))
		return ErrClientNotInitialized
	}

	var err error

	// Ensure that metadata exists for this lock
	err = s.LockEnsureMetadata(ctx, path)
	if err != nil {
		s.logger.Debug("Ensuring metadata for lock failed", zap.String("path", path), zap.Error(err))
		return err
	}

	data := map[string]interface{}{
		"locked": true,  // This does not mean anything, but is better than nothing
	}

	var lockInfo LockInfo
	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			s.logger.Debug("Locking failed", zap.String("path", path), zap.Error(ErrRetriesExceeded))
			return ErrRetriesExceeded
		}

		// Check if lock is taken
		for {
			lockVersionRaw, lockExists := s.lockVersions.Load(path)
			if (lockExists) {
				lockVersion, ok := lockVersionRaw.(int)
				if ok {
					s.logger.Debug("Lock already taken (locally)", zap.String("path", path), zap.Int("version", lockVersion))
				} else {
					s.logger.Debug("Lock already taken (locally)", zap.String("path", path))
				}				
				// Wait a while
				time.Sleep(time.Duration(s.LockCheckInterval) * time.Second)
			}

			lockInfo, err = s.LockStat(ctx, path)
			if err != nil {
				if err == fs.ErrNotExist {
					s.logger.Debug("Fetched lock stat", zap.String("path", path), zap.Bool("exists", false))
					// There is no lock, so create it with the initial version
					lockInfo.Version = 0
					break
				} else {
					s.logger.Debug("Locking failed", zap.String("path", path), zap.Error(err))
					return err
				}
			}

			s.logger.Debug("Fetched lock stat", zap.String("path", path), zap.Bool("exists", true), zap.Bool("isLocked", lockInfo.IsLocked), zap.Int("version", lockInfo.Version), zap.Time("created", lockInfo.Created))

			if !lockInfo.IsLocked {
				// There was already a lock, that was freed
				break
			}

			if time.Now().Sub(lockInfo.Created) > (time.Duration(s.LockTimeout) * time.Second) {
				s.logger.Debug("Existing lock timed out", zap.String("path", path), zap.Int("version", lockInfo.Version))
				// The lock has timed out, so force unlock it
				lockInfo.IsLocked = false
				break
			} else {
				s.logger.Debug("Lock already taken", zap.String("path", path), zap.Int("version", lockInfo.Version))
				// Wait a while
				time.Sleep(time.Duration(s.LockCheckInterval) * time.Second)
			}
		}

		s.logger.Debug("Lock is free, trying to aquire it", zap.String("path", path), zap.Int("version", lockInfo.Version))

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		// The request is done with the check-and-set option, that ensures only one of concurrent
		// requests can get the lock, the others will fail
		_, err := s.client.KVv2(s.SecretsMountPath).Put(ctx, s.PrefixPath(path), data, vault.WithOption("cas", lockInfo.Version))
		s.connectionLock.RUnlock()
		if err != nil {
			var responseError *vault.ResponseError
			if errors.As(err, &responseError) {
				if responseError.StatusCode == 400 {
					s.logger.Debug("Lock was aquired in the meantime, retrying", zap.String("path", path), zap.Int("version", lockInfo.Version))
					// The lock was already taken by another request, so try again
					i++  // Don't count this retry as a connection retry
					continue
				}
			}

			retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
			if retryErr != nil {
				s.logger.Debug("Locking failed", zap.String("path", path), zap.Error(retryErr))
				return retryErr
			}
			if (!retry) {
				s.logger.Debug("Locking failed", zap.String("path", path), zap.Error(err))
				return err
			}
			// Retry connection
			s.logger.Warn("Retrying request after error", zap.String("operation", "lock"), zap.String("path", path), zap.Error(err))
		} else {
			// The lock was taken successfully
			break
		}
	}

	s.lockVersions.Store(path, lockInfo.Version + 1)
	s.logger.Debug("Locked successfully", zap.String("path", path))
	return nil
}

/**
 * Ensures, that metadata exists for a lock. This only has to be done once,
 * but is idempotent.
 */
func (s *VaultStorage) LockEnsureMetadata(ctx context.Context, path string) error {
	if s.client == nil {
		return ErrClientNotInitialized
	}

	path = strings.Trim(path, "/")

	metadata := vault.KVMetadataPutInput{
		CASRequired: true,  // The check-and-set ensures that no two concurrent requests can get the lock
		MaxVersions: 1,  // Don't save the other lock versions
		DeleteVersionAfter: time.Duration(s.LockTimeout) * time.Second,  // Automated server-side lock timeout
	}

	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			return ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		err := s.client.KVv2(s.SecretsMountPath).PutMetadata(ctx, s.PrefixPath(path), metadata)
		s.connectionLock.RUnlock()
		if err != nil {
			retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
			if retryErr != nil {
				return retryErr
			}
			if (!retry) {
				return err
			}
			// Retry connection
			s.logger.Warn("Retrying request after error", zap.String("operation", "lock-metadata"), zap.String("path", path), zap.Error(err))
		} else {
			// The lock metadata request was successfull
			break
		}
	}

	return nil
}

/**
 * Retreives information about a specific lock.
 */
func (s *VaultStorage) LockStat(ctx context.Context, path string) (LockInfo, error) {
	lockInfo := LockInfo{
		Created: time.Time{},
		Version: -1,
		IsLocked: false,
	}

	if s.client == nil {
		return lockInfo, ErrClientNotInitialized
	}

	path = strings.Trim(path, "/")

	var metadata *vault.KVMetadata
	var err error
	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			return lockInfo, ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		metadata, err = s.client.KVv2(s.SecretsMountPath).GetMetadata(ctx, s.PrefixPath(path))
		s.connectionLock.RUnlock()
		if err != nil {
			if errors.Is(err, vault.ErrSecretNotFound) {
				return lockInfo, fs.ErrNotExist
			} else {
				retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
				if retryErr != nil {
					return lockInfo, retryErr
				}
				if (!retry) {
					return lockInfo, err
				}
				// Retry connection
				s.logger.Warn("Retrying request after error", zap.String("operation", "lock-stat"), zap.String("path", path), zap.Error(err))
			}
		} else {
			// The lock metadata request was successfull
			break
		}
	}

	// Check if the current version of the lock was soft-deleted 
	isAlive := true
	versionMetadata, ok := metadata.Versions[strconv.Itoa(metadata.CurrentVersion)]
	if !ok {
		if metadata.CurrentVersion > 0 {
			// The version zero doesn't has metadata, but every other version should
			s.logger.Warn("Couldn't determine whether lock was freed", zap.String("path", path), zap.Int("version", metadata.CurrentVersion))
		}
	} else {
		lockInfo.Created = versionMetadata.CreatedTime

		// Check wether lock was soft-deleted
		if versionMetadata.DeletionTime.After(time.Time{}) && time.Now().After(versionMetadata.DeletionTime) {
			isAlive = false
		}
	}

	lockInfo.Version = metadata.CurrentVersion
	// The version zero means, that metadata exists, but no value, so the lock is free to be taken
	lockInfo.IsLocked = metadata.CurrentVersion > 0 && isAlive

	return lockInfo, nil
}

/**
 * Frees an existing lock. Throws the error fs.ErrNotExist if there was no lock
 * found, that was aquired on this vault storge module instance.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Locker
 */
func (s *VaultStorage) Unlock(ctx context.Context, path string) error {
	path = strings.Trim(path, "/")

	s.logger.Debug("Unlocking", zap.String("path", path))

	if s.client == nil {
		s.logger.Debug("Unlocking failed", zap.String("path", path), zap.Error(ErrClientNotInitialized))
		return ErrClientNotInitialized
	}

	lockVersionRaw, lockExists := s.lockVersions.LoadAndDelete(path)
	if !lockExists {
		s.logger.Debug("Unlocking failed", zap.String("path", path), zap.Error(fs.ErrNotExist))
		return fs.ErrNotExist
	}

	lockVersion, ok := lockVersionRaw.(int)
	if !ok {
		s.logger.Debug("Unlocking failed", zap.String("path", path), zap.Error(ErrInvalidValue))
		return ErrInvalidValue
	}

	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			s.logger.Debug("Unlocking failed", zap.String("path", path), zap.Error(ErrRetriesExceeded))
			return ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		err := s.client.KVv2(s.SecretsMountPath).DeleteVersions(ctx, s.PrefixPath(path), []int{lockVersion})
		s.connectionLock.RUnlock()
		if err != nil {
			if errors.Is(err, vault.ErrSecretNotFound) {
				s.logger.Debug("Unlocked successfully", zap.String("path", path))
				return nil
			} else {
				retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
				if retryErr != nil {
					s.logger.Debug("Unlocking failed", zap.String("path", path), zap.Error(retryErr))
					return retryErr
				}
				if (!retry) {
					s.logger.Debug("Unlocking failed", zap.String("path", path), zap.Error(err))
					return err
				}
				// Retry connection
				s.logger.Warn("Retrying request after error", zap.String("operation", "unlock"), zap.String("path", path), zap.Error(err))
			}
		} else {
			// The deletion request was successfull
			break
		}
	}

	s.logger.Debug("Unlocked successfully", zap.String("path", path))
	return nil
}

/**
 * Creates or updates a value in the key-value store.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Storage
 */
func (s *VaultStorage) Store(ctx context.Context, path string, value []byte) error {
	path = strings.Trim(path, "/")

	s.logger.Debug("Storing", zap.String("path", path))

	if s.client == nil {
		return ErrClientNotInitialized
	}

	err := s.StoreEnsureMetadata(ctx, path)
	if err != nil {
		s.logger.Debug("Ensuring metadata for store failed", zap.String("path", path), zap.Error(err))
		return err
	}

	data := map[string]interface{}{
		"base64": base64.StdEncoding.EncodeToString(value),
	}

	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			s.logger.Debug("Storing failed", zap.String("path", path), zap.Error(ErrRetriesExceeded))
			return ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		_, err := s.client.KVv2(s.SecretsMountPath).Put(ctx, s.PrefixPath(path), data)
		s.connectionLock.RUnlock()
		if err != nil {
			retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
			if retryErr != nil {
				s.logger.Debug("Storing failed", zap.String("path", path), zap.Error(retryErr))
				return retryErr
			}
			if (!retry) {
				s.logger.Debug("Storing failed", zap.String("path", path), zap.Error(err))
				return err
			}
			// Retry connection
			s.logger.Warn("Retrying request after error", zap.String("operation", "store"), zap.String("path", path), zap.Error(err))
		} else {
			// The store request was successfull
			break
		}
	}

	s.logger.Debug("Stored successfully", zap.String("path", path))
	return nil
}

/**
 * Ensures, that metadata exists for a key in the key-value store. This only
 * has to be done once, but is idempotent.
 */
func (s *VaultStorage) StoreEnsureMetadata(ctx context.Context, path string) error {
	if s.client == nil {
		return ErrClientNotInitialized
	}

	path = strings.Trim(path, "/")

	metadata := vault.KVMetadataPutInput{
		CASRequired: false,
		MaxVersions: 1,
	}

	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			return ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		err := s.client.KVv2(s.SecretsMountPath).PutMetadata(ctx, s.PrefixPath(path), metadata)
		s.connectionLock.RUnlock()
		if err != nil {
			retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
			if retryErr != nil {
				return retryErr
			}
			if (!retry) {
				return err
			}
			// Retry connection
			s.logger.Warn("Retrying request after error", zap.String("operation", "store-metadata"), zap.String("path", path), zap.Error(err))
		} else {
			// The store metadata request was successfull
			break
		}
	}

	return nil
}

/**
 * Retreives a value from the key-value store. Throws the error fs.ErrNotExist
 * if no value exists for the key.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Storage
 */
func (s *VaultStorage) Load(ctx context.Context, path string) ([]byte, error) {
	path = strings.Trim(path, "/")

	s.logger.Debug("Loading", zap.String("path", path))

	if s.client == nil {
		return nil, ErrClientNotInitialized
	}

	var secret *vault.KVSecret
	var err error
	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			return nil, ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		secret, err = s.client.KVv2(s.SecretsMountPath).Get(ctx, s.PrefixPath(path))
		s.connectionLock.RUnlock()
		if err != nil {
			if errors.Is(err, vault.ErrSecretNotFound) {
				// There exists no value in this key
				s.logger.Debug("Loading failed", zap.String("path", path), zap.Error(fs.ErrNotExist))
				return nil, fs.ErrNotExist
			} else {
				retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
				if retryErr != nil {
					s.logger.Debug("Loading failed", zap.String("path", path), zap.Error(retryErr))
					return nil, retryErr
				}
				if (!retry) {
					s.logger.Debug("Loading failed", zap.String("path", path), zap.Error(err))
					return nil, err
				}
				// Retry connection
				s.logger.Warn("Retrying request after error", zap.String("operation", "load"), zap.String("path", path), zap.Error(err))
			}
		} else {
			// The load request was successfull
			break
		}
	}

	if secret == nil {
		// There exists no value in this key
		s.logger.Debug("Loading failed", zap.String("path", path), zap.Error(fs.ErrNotExist))
		return nil, fs.ErrNotExist
	}

	data, ok := secret.Data["base64"].(string)
	if !ok {
		// The data in this key is not in our format, so report an error
		s.logger.Debug("Loading failed", zap.String("path", path), zap.Error(ErrInvalidValue))
		return nil, ErrInvalidValue
	}

	value, err := base64.StdEncoding.DecodeString(data) 
	if err != nil {
		s.logger.Debug("Loading failed", zap.String("path", path), zap.Error(err))
		return nil, err
	}

	s.logger.Debug("Loaded successfully", zap.String("path", path))
	return value, nil
}

/**
 * Check whether a key exists in the key-value store. On error, false will be
 * returned.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Storage
 */
func (s *VaultStorage) Exists(ctx context.Context, path string) bool {
	_, err := s.Stat(ctx, path)

	// If the path exists, the stat function terminated successfully
	return err == nil
}

/**
 * Deletes a value in the key-value store. Throws the error fs.ErrNotExist
 * if no value exists for the key.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Storage
 */
func (s *VaultStorage) Delete(ctx context.Context, path string) error {
	path = strings.Trim(path, "/")

	s.logger.Debug("Deleting", zap.String("path", path))

	if s.client == nil {
		s.logger.Debug("Deleting failed", zap.String("path", path), zap.Error(ErrClientNotInitialized))
		return ErrClientNotInitialized
	}

	// Get the stat information for this path
	pathInfo, err := s.Stat(ctx, path)
	if err != nil {
		if err == fs.ErrNotExist {
			s.logger.Debug("Deleted successfully (there was nothing)", zap.String("path", path))
			return nil
		} else {
			s.logger.Debug("Deleting failed", zap.String("path", path), zap.Error(err))
		}
		return err  // This includes fs.ErrNotExist
	}

	var filePathsToDelete []string

	// If it's a file, delete it directly
	if pathInfo.IsTerminal {
		filePathsToDelete = append(filePathsToDelete, path)
	} else {
		// If it's a directory, delete everything in it
		filePathsToDelete, err = s.List(ctx, path, true)
		if err != nil {
			s.logger.Debug("Deleting failed", zap.String("path", path), zap.Error(err))
			return err
		}
	}

	s.logger.Debug("Enumerated files to delete", zap.String("path", path), zap.Int("count", len(filePathsToDelete)))

	for _, filePath := range filePathsToDelete {
		for i := s.MaxRetries; true; i-- {
			if (i <= 0) {
				s.logger.Debug("Deleting failed", zap.String("path", path), zap.Error(ErrRetriesExceeded))
				return ErrRetriesExceeded
			}

			s.connectionLock.RLock()
			clientAddressTried := s.client.Address()
			err := s.client.KVv2(s.SecretsMountPath).DeleteMetadata(ctx, s.PrefixPath(filePath))
			s.connectionLock.RUnlock()
			if err != nil {
				retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
				if retryErr != nil {
					s.logger.Debug("Deleting failed", zap.String("path", path), zap.Error(retryErr))
					return retryErr
				}
				if (!retry) {
					s.logger.Debug("Deleting failed", zap.String("path", path), zap.Error(err))
					return err
				}
				// Retry connection
				s.logger.Warn("Retrying request after error", zap.String("operation", "delete"), zap.String("path", filePath), zap.String("deletionPath", path), zap.Error(err))
			} else {
				// The deletion request was successfull
				break
			}
		}
	}

	s.logger.Debug("Deleted successfully", zap.String("path", path))
	return nil
}

/**
 * Retreives stat information about a value in the key-value store. Throws the
 * error fs.ErrNotExist, if no value exists for the key.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Storage
 */
func (s *VaultStorage) Stat(ctx context.Context, path string) (certmagic.KeyInfo, error) {
	path = strings.Trim(path, "/")

	s.logger.Debug("Stating", zap.String("path", path))

	keyInfo := certmagic.KeyInfo{
		Key: path,
		IsTerminal: false,
	}

	if s.client == nil {
		s.logger.Debug("Stating failed", zap.String("path", path), zap.Error(ErrClientNotInitialized))
		return keyInfo, ErrClientNotInitialized
	}

	var metadata *vault.KVMetadata
	var err error
	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			s.logger.Debug("Stating failed", zap.String("path", path), zap.Error(ErrRetriesExceeded))
			return keyInfo, ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		metadata, err = s.client.KVv2(s.SecretsMountPath).GetMetadata(ctx, s.PrefixPath(path))
		s.connectionLock.RUnlock()
		if err != nil {
			if errors.Is(err, vault.ErrSecretNotFound) {
				// There exists no value on this path, so check whether it's
				// a directory
				exists, existsErr := s.StatCheckDirectory(ctx, path)
				if existsErr != nil {
					s.logger.Debug("Stating failed", zap.String("path", path), zap.Error(existsErr))
					return keyInfo, existsErr
				}
				if exists {
					// This is a directory
					keyInfo.IsTerminal = false
					s.logger.Debug("Stated successfully", zap.String("path", path), zap.Bool("exists", true), zap.Bool("isTerminal", keyInfo.IsTerminal), zap.Time("modified", keyInfo.Modified))
					return keyInfo, nil
				} else {
					s.logger.Debug("Stated successfully", zap.String("path", path), zap.Bool("exists", false))
					return keyInfo, fs.ErrNotExist
				}
			} else {
				retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
				if retryErr != nil {
					s.logger.Debug("Stating failed", zap.String("path", path), zap.Error(retryErr))
					return keyInfo, retryErr
				}
				if (!retry) {
					s.logger.Debug("Stating failed", zap.String("path", path), zap.Error(err))
					return keyInfo, err
				}
				// Retry connection
				s.logger.Warn("Retrying request after error", zap.String("operation", "stat"), zap.String("path", path), zap.Error(err))
			}
		} else {
			// The metadata request was successfull
			break
		}
	}

	keyInfo.IsTerminal = true

	// Check if the current version of the value was soft-deleted
	wasDeleted := false
	versionMetadata, ok := metadata.Versions[strconv.Itoa(metadata.CurrentVersion)]
	if !ok {
		s.logger.Debug("Version metadata is missing data for current version", zap.String("path", path), zap.Int("version", metadata.CurrentVersion), zap.Any("versionMetadata", versionMetadata))
		return keyInfo, ErrInvalidResponse
	} else {
		keyInfo.Modified = versionMetadata.CreatedTime
		if versionMetadata.DeletionTime.After(time.Time{}) && time.Now().After(versionMetadata.DeletionTime) {
			wasDeleted = true
		}
	}

	if wasDeleted {
		// The value was soft-deleted, so report it doesn't exist
		s.logger.Debug("Stated successfully", zap.String("path", path), zap.Bool("exists", false))
		return keyInfo, fs.ErrNotExist
	} else {
		// There exists a value, so report it's information
		s.logger.Debug("Stated successfully", zap.String("path", path), zap.Bool("exists", true), zap.Bool("isTerminal", keyInfo.IsTerminal), zap.Time("modified", keyInfo.Modified))
		return keyInfo, nil
	}
}

/**
 * Checks whether a directory exits on a given path. Files will report as false.
 */
func (s *VaultStorage) StatCheckDirectory(ctx context.Context, path string) (bool, error) {
	if s.client == nil {
		return false, ErrClientNotInitialized
	}

	path = strings.Trim(path, "/")

	var response *vault.Secret
	var err error
	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			return false, ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		response, err = s.client.Logical().ListWithContext(ctx, s.SecretsMountPath + "/metadata/" + s.PrefixPath(path))
		s.connectionLock.RUnlock()
		if err != nil {
			retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
			if retryErr != nil {
				return false, retryErr
			}
			if (!retry) {
				return false, err
			}
			// Retry connection
			s.logger.Warn("Retrying request after error", zap.String("operation", "stat-check-directory"), zap.String("path", path), zap.Error(err))
		} else {
			// The list request was successfull
			break
		}
	}

	// If there was data returned, something exists beneath the path
	return response != nil, nil
}

/**
 * List all existing keys in a specific path.
 * 
 * @see https://pkg.go.dev/github.com/caddyserver/certmagic#Storage
 */
func (s *VaultStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	path = strings.Trim(path, "/")

	s.logger.Debug("Listing", zap.String("path", path))

	if s.client == nil {
		s.logger.Debug("Listing failed", zap.String("path", path), zap.Error(ErrClientNotInitialized))
		return nil, ErrClientNotInitialized
	}

	// Get the stat information for this path
	pathInfo, err := s.Stat(ctx, path)
	if err != nil {
		s.logger.Debug("Listing failed", zap.String("path", path), zap.Error(err))
		return nil, err  // This includes fs.ErrNotExist
	}

	if pathInfo.IsTerminal {
		// This is a file, so list the file itself
		return []string{path}, nil
	}

	// Aggregate all file paths in this directory
	filePathsAggregator := list.New()
	err = s.ListAggregate(ctx, path, recursive, filePathsAggregator, true)
	if err != nil {
		s.logger.Debug("Listing failed", zap.String("path", path), zap.Error(err))
		return nil, err
	}

	// Type conversion
	var filePaths []string
	for e := filePathsAggregator.Front(); e != nil; e = e.Next() {
		filePath, ok := e.Value.(string)
		if !ok {
			s.logger.Warn("Skipped value in listing, because it's not a string")
			continue
		}
		filePaths = append(filePaths, filePath)
	}

	s.logger.Debug("Listed successfully", zap.String("path", path))
	return filePaths, nil
}

/**
 * Internal aggregator for existing keys in a specific path.
 */
func (s *VaultStorage) ListAggregate(ctx context.Context, path string, recursive bool, filePathsAggregator *list.List, keyExistsCheck bool) error {
	if s.client == nil {
		return ErrClientNotInitialized
	}

	path = strings.Trim(path, "/")

	var secret *vault.Secret
	var err error
	for i := s.MaxRetries; true; i-- {
		if (i <= 0) {
			return ErrRetriesExceeded
		}

		s.connectionLock.RLock()
		clientAddressTried := s.client.Address()
		secret, err = s.client.Logical().ListWithContext(ctx, s.SecretsMountPath + "/metadata/" + s.PrefixPath(path))
		s.connectionLock.RUnlock()
		if err != nil {
			retry, retryErr := s.ReconnectOnError(ctx, err, clientAddressTried)
			if retryErr != nil {
				return retryErr
			}
			if (!retry) {
				return err
			}
			// Retry connection
			s.logger.Warn("Retrying request after error", zap.String("operation", "list-aggregate"), zap.String("path", path), zap.Error(err))
		} else {
			// The list request was successfull
			break
		}
	}

	if secret == nil {
		// No directory exists on the path
		return fs.ErrNotExist
	}

	subPathsRaw, ok := secret.Data["keys"].([]interface{});
	if !ok {
		return ErrInvalidResponse
	}

	for _, subPathRaw := range subPathsRaw {
		subPath, ok := subPathRaw.(string);
		if !ok {
			return ErrInvalidResponse
		}

		fullSubPath := strings.Trim(path + "/" + subPath, "/")

		if strings.HasSuffix(subPath, "/") {
			if recursive {
				err = s.ListAggregate(ctx, fullSubPath, recursive, filePathsAggregator, keyExistsCheck)
				if err != nil {
					return err
				}
			}
		} else if keyExistsCheck {
			pathInfo, err := s.Stat(ctx, fullSubPath)
			if err != nil && err != fs.ErrNotExist {
				return err
			}
			if err == nil && pathInfo.IsTerminal {
				filePathsAggregator.PushBack(fullSubPath)
			}
		} else {
			filePathsAggregator.PushBack(fullSubPath)
		}
	}

	return nil
}
