package tunnel

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/testleaks"
)

func TestRegistryAddRemoveList(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewRegistry()
	info1 := TunnelInfo{
		ID: uuid.New(), AccountID: uuid.New(), DeploymentID: uuid.New(),
		Generation: 1, StartedAt: time.Now(), ConnectionID: "conn-1",
	}
	info2 := TunnelInfo{
		ID: uuid.New(), AccountID: uuid.New(), DeploymentID: uuid.New(),
		Generation: 2, StartedAt: time.Now(), ConnectionID: "conn-2",
	}

	r.Add(info1)
	r.Add(info2)

	list := r.List()
	if len(list) != 2 {
		t.Errorf("List len = %d, want 2", len(list))
	}

	r.Remove(info1.ID)

	list = r.List()
	if len(list) != 1 {
		t.Errorf("List len after remove = %d, want 1", len(list))
	}
	if list[0].ID != info2.ID {
		t.Errorf("List[0].ID = %v, want %v", list[0].ID, info2.ID)
	}
}

func TestRegistryCountForAccount(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewRegistry()
	accountID := uuid.New()

	for i := 0; i < 5; i++ {
		r.Add(TunnelInfo{
			ID: uuid.New(), AccountID: accountID, DeploymentID: uuid.New(),
			Generation: int64(i), StartedAt: time.Now(), ConnectionID: "conn",
		})
	}
	r.Add(TunnelInfo{
		ID: uuid.New(), AccountID: uuid.New(), DeploymentID: uuid.New(),
		Generation: 10, StartedAt: time.Now(), ConnectionID: "conn-other",
	})

	count := r.CountForAccount(accountID)
	if count != 5 {
		t.Errorf("CountForAccount = %d, want 5", count)
	}
}

func TestRegistryConcurrent(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewRegistry()
	var done atomic.Int32
	start := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func(idx int) {
			<-start
			info := TunnelInfo{
				ID: uuid.New(), AccountID: uuid.New(), DeploymentID: uuid.New(),
				Generation: int64(idx), StartedAt: time.Now(), ConnectionID: "conn",
			}
			r.Add(info)
			r.List()
			r.CountForAccount(info.AccountID)
			r.Remove(info.ID)
			done.Add(1)
		}(i)
	}

	close(start)

	for done.Load() != 50 {
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRegistryBoundedEviction(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewRegistry()
	accountID := uuid.New()

	for i := 0; i < registryMaxSize+100; i++ {
		r.Add(TunnelInfo{
			ID: uuid.New(), AccountID: accountID, DeploymentID: uuid.New(),
			Generation: int64(i), StartedAt: time.Now(), ConnectionID: "conn",
		})
	}

	count := r.CountForAccount(accountID)
	if count != registryMaxSize {
		t.Errorf("CountForAccount = %d, want %d (bounded)", count, registryMaxSize)
	}
}

func TestRegistryRace(t *testing.T) {
	defer testleaks.Verify(t)

	r := NewRegistry()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := TunnelInfo{
				ID: uuid.New(), AccountID: uuid.New(), DeploymentID: uuid.New(),
				Generation: 1, StartedAt: time.Now(), ConnectionID: "conn",
			}
			r.Add(info)
			r.List()
			r.CountForAccount(info.AccountID)
			r.Remove(info.ID)
		}()
	}

	wg.Wait()
}
