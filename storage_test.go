package caddy_vault_storage

import (
	"container/list"
	"context"
	"errors"
	"net/url"
	"strings"
	"slices"
	"sync"
	"testing"
	"time"
	"os"
	"io/fs"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"go.uber.org/zap"
)

func Setup(t *testing.T, ctx context.Context) *VaultStorage {
	assert.Assert(t, os.Getenv("VAULT_STORAGE_ADDRS") != "")
	assert.Assert(t, os.Getenv("VAULT_TOKEN") != "")

	s := New()
	s.logger = zap.Must(zap.NewDevelopment())
	s.SecretsPathPrefix = "caddy-test"
	s.Addresses = strings.Split(os.Getenv("VAULT_STORAGE_ADDRS"), ",")

	assert.NilError(t, s.Connect(ctx))

	Cleanup(t, ctx, s)
	t.Cleanup(func() {
		Cleanup(t, ctx, s)
	})

	return s
}

func Cleanup(t *testing.T, ctx context.Context, s *VaultStorage) {
	filePathsAggregator := list.New()
	err := s.ListAggregate(ctx, "", true, filePathsAggregator, false)
	if err != nil {
		return
	}

	for e := filePathsAggregator.Front(); e != nil; e = e.Next() {
		filePath, ok := e.Value.(string)
		if !ok {
			s.logger.Warn("Skipped value in listing, because it's not a string")
			continue
		}
		assert.NilError(t, s.client.KVv2(s.SecretsMountPath).DeleteMetadata(ctx, s.PrefixPath(filePath)))
	}
}

/**
 * Check connection establishment
 */
func TestConnect(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)

	s.Addresses = []string{}
	assert.ErrorType(t, s.Connect(ctx), ErrNoServersConfigured)

	s.Addresses = []string{"https://unreachable"}
	assert.ErrorType(t, s.Connect(ctx), ErrAllServersUnavailable)
}

/**
 * Check the capabilities check
 */
func TestCheckCapabilities(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)

	assert.NilError(t, s.CheckCapabilities(ctx))
}

/**
 * Check reconnection functionality
 */
func TestReconnect(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)
	s.client.SetClientTimeout(10 * time.Second)

	if len(s.Addresses) < 2 {
		return
	}

	value := []byte("e7e2Q6wX06G3QhtenfAKvs+vSwMBm0uJWRUj3KnS+jc=")

	assert.NilError(t, s.Store(ctx, "937a8b76eca465db", value))

	s.client.SetAddress("https://unreachable")
	loadedValue, err := s.Load(ctx, "937a8b76eca465db")
	assert.NilError(t, err)
	assert.Equal(t, string(loadedValue), string(value))

	reconnect, err := s.ReconnectOnError(ctx, &url.Error{}, s.Addresses[0])
	assert.NilError(t, err)
	assert.Equal(t, reconnect, true)
	assert.Assert(t, s.client.Address() != s.Addresses[0])

	reconnect, err = s.ReconnectOnError(ctx, errors.New("Unrecoverable error"), s.Addresses[0])
	assert.NilError(t, err)
	assert.Equal(t, reconnect, false)

	s.Addresses = []string{s.Addresses[0]}
	reconnect, err = s.ReconnectOnError(ctx, nil, s.Addresses[0])
	assert.NilError(t, err)
	assert.Equal(t, reconnect, false)
}

/**
 * Stores a value, tries to load it and then compares the result
 */
func TestStoreAndLoad(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)

	value := []byte("bFnc6v0ixNdbAOMhkscLsGG0EFq155WD2F2uKPuuCfA=")

	assert.NilError(t, s.Store(ctx, "b069bbddd265c34f", value))

	loadedValue, err := s.Load(ctx, "b069bbddd265c34f")
	assert.NilError(t, err)
	assert.Equal(t, string(loadedValue), string(value))

	// Update the value and repeat the process

	value = []byte("IsOva0p1ZMBNPJoJXQh1CVTN0/jm/EFYZAXX9qxQpYc=")

	assert.NilError(t, s.Store(ctx, "b069bbddd265c34f", value))

	loadedValue, err = s.Load(ctx, "b069bbddd265c34f")
	assert.NilError(t, err)
	assert.Equal(t, string(loadedValue), string(value))
}


/**
 * Creates a value, checks it's (and it's parents path) existence, then deletes
 * it and checking that again
 */
func TestDeleteAndStat(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)

	value := []byte("8FNwXAQb2/i6tUOgrS9yoUWN0HK3s5C74GlyAXYxlEE=")

	assert.NilError(t, s.Store(ctx, "ba/0b/c0f5721f02", value))

	pathInfo, err := s.Stat(ctx, "ba/0b/c0f5721f02")
	assert.NilError(t, err)
	assert.Equal(t, pathInfo.IsTerminal, true)

	assert.Equal(t, s.Exists(ctx, "ba/0b/c0f5721f02"), true)

	pathInfo, err = s.Stat(ctx, "ba/0b")
	assert.NilError(t, err)
	assert.Equal(t, pathInfo.IsTerminal, false)

	assert.Equal(t, s.Exists(ctx, "ba/0b"), true)

	assert.NilError(t, s.Delete(ctx, "ba/0b/c0f5721f02"))

	pathInfo, err = s.Stat(ctx, "ba/0b/c0f5721f02")
	assert.ErrorType(t, err, fs.ErrNotExist)

	assert.Equal(t, s.Exists(ctx, "ba/0b/c0f5721f02"), false)

	pathInfo, err = s.Stat(ctx, "ba/0b")
	if err != nil {
		assert.ErrorType(t, err, fs.ErrNotExist)
	} else {
		assert.Equal(t, pathInfo.IsTerminal, false)
	}
}

/**
 * Creates multiple values, checks their existence (via listing), deletes a
 * parent path and checks their existence again
 */
func TestDeleteAndList(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)

	value := []byte("TYrqeLz4xvsIa/9mbx0+Y9xVMz8FpHU3ah36RLWuDSQ=")

	assert.NilError(t, s.Store(ctx, "25/e8/bef5d4a31e", value))
	assert.NilError(t, s.Store(ctx, "25/997f8f89104e8", value))

	paths, err := s.List(ctx, "25", true)
	assert.NilError(t, err)
	assert.Assert(t, len(paths) == 2)
	assert.Assert(t, slices.Contains(paths, "25/e8/bef5d4a31e"))
	assert.Assert(t, slices.Contains(paths, "25/997f8f89104e8"))

	paths, err = s.List(ctx, "25", false)
	assert.NilError(t, err)
	assert.Assert(t, len(paths) == 1)
	assert.Assert(t, slices.Contains(paths, "25/997f8f89104e8"))

	assert.NilError(t, s.Delete(ctx, "25"))

	paths, err = s.List(ctx, "25", true)
	if err != nil {
		assert.ErrorType(t, err, fs.ErrNotExist)
	} else {
		assert.Assert(t, len(paths) == 0)
	}
}

/**
 * Runs the Load, Stat, Exists, Lists, Delete and Unlock operations on
 * non-existing keys and checks their error behavior.
 */
func TestNonExisting(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)

	_, err := s.Load(ctx, "9a/47/e976247ff8")
	assert.ErrorType(t, err, fs.ErrNotExist)

	_, err = s.Stat(ctx, "44/a4/522e570167")
	assert.ErrorType(t, err, fs.ErrNotExist)

	assert.Equal(t, s.Exists(ctx, "1c/67/ceefbadb73"), false)

	_, err = s.List(ctx, "2b/3e", true)
	assert.ErrorType(t, err, fs.ErrNotExist)

	_, err = s.List(ctx, "0e/bb", false)
	assert.ErrorType(t, err, fs.ErrNotExist)

	err = s.Delete(ctx, "69/ed/30aa55bcf7")
	assert.NilError(t, err)

	assert.ErrorType(t, s.Unlock(ctx, "52251b03e95f8539"), fs.ErrNotExist)
}

/**
 * Creates locks one after another and checks whether timing seems right and
 * internal data is set correctly
 */
func TestLockingBasic(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)
	s.LockTimeout = 5
	s.LockCheckInterval = 6

	startTime := time.Now()
	assert.NilError(t, s.Lock(ctx, "1de198d4d777f04a"))
	endTime := time.Now()

	assert.Assert(t, endTime.Sub(startTime).Seconds() < 4)

	lockVersion, lockExists := s.lockVersions.Load("1de198d4d777f04a")
	assert.Equal(t, lockExists, true)
	assert.Equal(t, lockVersion, 1)

	assert.NilError(t, s.Unlock(ctx, "1de198d4d777f04a"))

	lockVersion, lockExists = s.lockVersions.Load("1de198d4d777f04a")
	assert.Equal(t, lockExists, false)

	// Check a second time

	startTime = time.Now()
	assert.NilError(t, s.Lock(ctx, "1de198d4d777f04a"))
	endTime = time.Now()

	assert.Assert(t, endTime.Sub(startTime).Seconds() < 4)

	lockVersion, lockExists = s.lockVersions.Load("1de198d4d777f04a")
	assert.Equal(t, lockExists, true)
	assert.Equal(t, lockVersion, 2)

	assert.NilError(t, s.Unlock(ctx, "1de198d4d777f04a"))

	lockVersion, lockExists = s.lockVersions.Load("1de198d4d777f04a")
	assert.Equal(t, lockExists, false)
}

/**
 * Creates concurrent locks on a local client and checks whether timing seems
 * right and internal data is set correctly
 */
func TestLockingConcurrentLocally(t *testing.T) {
	ctx := context.Background()
	s := Setup(t, ctx)
	s.LockTimeout = 15
	s.LockCheckInterval = 2

	var waitGroup sync.WaitGroup
    waitGroup.Add(2)

    defer waitGroup.Wait()

    // Contender one holds the lock for 10 seconds
    go func() {
    	defer waitGroup.Done()

    	startTime := time.Now()
		assert.NilError(t, s.Lock(ctx, "fc295a2774eddc97"))
		endTime := time.Now()

		assert.Assert(t, endTime.Sub(startTime).Seconds() < 4)

		lockVersion, lockExists := s.lockVersions.Load("fc295a2774eddc97")
		assert.Equal(t, lockExists, true)
		assert.Equal(t, lockVersion, 1)

		s.logger.Debug("Contender 1 is waiting...")
		time.Sleep(6 * time.Second)

		assert.NilError(t, s.Unlock(ctx, "fc295a2774eddc97"))
    }()

    // Contender two waits 3 seconds, before trying to get the lock that is
    // holded by contender one
    go func() {
    	defer waitGroup.Done()

    	s.logger.Debug("Contender 2 is waiting...")
    	time.Sleep(2 * time.Second)

    	startTime := time.Now()
		assert.NilError(t, s.Lock(ctx, "fc295a2774eddc97"))
		endTime := time.Now()

		assert.Assert(t, endTime.Sub(startTime).Seconds() > 3)
		assert.Assert(t, endTime.Sub(startTime).Seconds() < 9)

		lockVersion, lockExists := s.lockVersions.Load("fc295a2774eddc97")
		assert.Equal(t, lockExists, true)
		assert.Equal(t, lockVersion, 2)

		assert.NilError(t, s.Unlock(ctx, "fc295a2774eddc97"))
    }()
}

/**
 * Creates concurrent locks on different clients to simulate distinct requests
 * being made to the server and checks whether timing seems right
 */
func TestLockingConcurrentRemotely(t *testing.T) {
	ctx := context.Background()
	s1 := Setup(t, ctx)
	s1.LockTimeout = 15
	s1.LockCheckInterval = 2

	s2 := Setup(t, ctx)
	s2.LockTimeout = 15
	s2.LockCheckInterval = 2

	s3 := Setup(t, ctx)
	s3.LockTimeout = 15
	s3.LockCheckInterval = 2

	var waitGroup sync.WaitGroup
    waitGroup.Add(3)

    defer waitGroup.Wait()

    // Contender one holds the lock for 10 seconds
    go func() {
    	defer waitGroup.Done()

    	startTime := time.Now()
		assert.NilError(t, s1.Lock(ctx, "fc295a2774eddc97"))
		endTime := time.Now()

		assert.Assert(t, endTime.Sub(startTime).Seconds() < 4)

		lockVersion, lockExists := s1.lockVersions.Load("fc295a2774eddc97")
		assert.Equal(t, lockExists, true)
		assert.Equal(t, lockVersion, 1)

		s1.logger.Debug("Contender 1 is waiting...")
		time.Sleep(6 * time.Second)

		assert.NilError(t, s1.Unlock(ctx, "fc295a2774eddc97"))
    }()

    // Contender two waits 3 seconds, before trying to get the lock that is
    // holded by contender one
    go func() {
    	defer waitGroup.Done()

    	s2.logger.Debug("Contender 2 is waiting...")
    	time.Sleep(2 * time.Second)

    	startTime := time.Now()
		assert.NilError(t, s2.Lock(ctx, "fc295a2774eddc97"))
		endTime := time.Now()

		assert.Assert(t, endTime.Sub(startTime).Seconds() > 3)
		assert.Assert(t, endTime.Sub(startTime).Seconds() < 9)

		lockVersion, lockExists := s2.lockVersions.Load("fc295a2774eddc97")
		assert.Equal(t, lockExists, true)
		assert.Assert(t, is.Contains([]int{2, 3}, lockVersion))

		s2.logger.Debug("Contender 2 got lock", zap.Any("version", lockVersion))

		assert.NilError(t, s2.Unlock(ctx, "fc295a2774eddc97"))
    }()

    // Contender three does the same as contender two
    go func() {
    	defer waitGroup.Done()

    	s3.logger.Debug("Contender 3 is waiting...")
    	time.Sleep(2 * time.Second)

    	startTime := time.Now()
		assert.NilError(t, s3.Lock(ctx, "fc295a2774eddc97"))
		endTime := time.Now()

		assert.Assert(t, endTime.Sub(startTime).Seconds() > 3)
		assert.Assert(t, endTime.Sub(startTime).Seconds() < 9)

		lockVersion, lockExists := s3.lockVersions.Load("fc295a2774eddc97")
		assert.Equal(t, lockExists, true)
		assert.Assert(t, is.Contains([]int{2, 3}, lockVersion))

		s3.logger.Debug("Contender 3 got lock", zap.Any("version", lockVersion))

		assert.NilError(t, s3.Unlock(ctx, "fc295a2774eddc97"))
    }()
}
