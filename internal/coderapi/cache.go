package coderapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

type cachedResult struct {
	accountID  uuid.UUID
	generation int64
	valid      bool
	coderID    uuid.UUID
	cachedAt   time.Time
}

// VerifyCaller is the minimal verifier surface CachedVerifier needs.
// *Verifier satisfies it; the T24 app assembly wraps the verifier with
// concurrency-limit and metrics instrumentation and passes the wrapper here.
type VerifyCaller interface {
	Verify(ctx context.Context, token []byte) (core.CoderIdentity, error)
}

type CachedVerifier struct {
	deploymentID uuid.UUID
	verifier     VerifyCaller
	ttl          time.Duration
	sfGroup      singleflight.Group
	mu           sync.Mutex
	cache        map[cacheKey]*cachedResult
}

type cacheKey struct {
	deploymentID uuid.UUID
	accountID    uuid.UUID
	generation   int64
}

func (k cacheKey) String() string {
	return k.deploymentID.String() + "/" + k.accountID.String() + "/" + strconv.FormatInt(k.generation, 10)
}

func NewCachedVerifier(deploymentID uuid.UUID, v VerifyCaller, ttl time.Duration) *CachedVerifier {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	return &CachedVerifier{
		deploymentID: deploymentID,
		verifier:     v,
		ttl:          ttl,
		cache:        make(map[cacheKey]*cachedResult),
	}
}

func (cv *CachedVerifier) VerifyCached(ctx context.Context, accountID uuid.UUID, generation int64, token []byte) (core.CoderIdentity, error) {
	key := cacheKey{
		deploymentID: cv.deploymentID,
		accountID:    accountID,
		generation:   generation,
	}

	v, err, _ := cv.sfGroup.Do(key.String(), func() (interface{}, error) {
		cv.mu.Lock()
		if entry, ok := cv.cache[key]; ok {
			if time.Since(entry.cachedAt) < cv.ttl {
				cv.mu.Unlock()
				if entry.valid {
					return core.CoderIdentity{ID: entry.coderID}, nil
				}
				return core.CoderIdentity{}, credErr(core.CredentialInvalid, 401, false,
					core.AUTH_CREDENTIAL_UNAUTHORIZED, nil)
			}
			delete(cv.cache, key)
		}
		cv.mu.Unlock()

		ident, err := cv.verifier.Verify(ctx, token)
		if err != nil {
			var ce *core.CredentialError
			if !errors.As(err, &ce) ||
				ce.Kind != core.CredentialInvalid ||
				ce.HTTPStatus != http.StatusUnauthorized {
				return ident, err
			}
			cv.mu.Lock()
			cv.cache[key] = &cachedResult{
				accountID:  accountID,
				generation: generation,
				valid:      false,
				cachedAt:   time.Now(),
			}
			cv.mu.Unlock()
			return ident, err
		}

		cv.mu.Lock()
		cv.cache[key] = &cachedResult{
			accountID:  accountID,
			generation: generation,
			valid:      true,
			coderID:    ident.ID,
			cachedAt:   time.Now(),
		}
		cv.mu.Unlock()
		return ident, nil
	})

	if err != nil {
		return core.CoderIdentity{}, err
	}
	return v.(core.CoderIdentity), nil
}

func (cv *CachedVerifier) Invalidate(accountID uuid.UUID, generation int64) {
	key := cacheKey{
		deploymentID: cv.deploymentID,
		accountID:    accountID,
		generation:   generation,
	}
	cv.mu.Lock()
	delete(cv.cache, key)
	cv.mu.Unlock()
}

func (cv *CachedVerifier) CacheStats() int {
	cv.mu.Lock()
	n := len(cv.cache)
	cv.mu.Unlock()
	return n
}
