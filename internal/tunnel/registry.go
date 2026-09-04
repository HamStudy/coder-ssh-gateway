package tunnel

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

const registryMaxSize = 10000

type TunnelInfo struct {
	ID           uuid.UUID
	AccountID    uuid.UUID
	DeploymentID uuid.UUID
	Generation   int64
	Route        core.Route
	StartedAt    time.Time
	ConnectionID string
}

type Registry struct {
	mu      sync.Mutex
	tunnels map[uuid.UUID]TunnelInfo
	order   []uuid.UUID
}

func NewRegistry() *Registry {
	return &Registry{
		tunnels: make(map[uuid.UUID]TunnelInfo),
		order:   make([]uuid.UUID, 0, 100),
	}
}

func (r *Registry) Add(info TunnelInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.tunnels) >= registryMaxSize {
		r.evictOldestLocked()
	}

	r.tunnels[info.ID] = info
	r.order = append(r.order, info.ID)
}

func (r *Registry) Remove(id uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tunnels, id)
}

func (r *Registry) List() []TunnelInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]TunnelInfo, 0, len(r.tunnels))
	for _, info := range r.tunnels {
		result = append(result, info)
	}
	return result
}

func (r *Registry) CountForAccount(accountID uuid.UUID) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, info := range r.tunnels {
		if info.AccountID == accountID {
			count++
		}
	}
	return count
}

func (r *Registry) evictOldestLocked() {
	if len(r.order) == 0 {
		return
	}
	oldest := r.order[0]
	delete(r.tunnels, oldest)
	r.order = r.order[1:]
}
