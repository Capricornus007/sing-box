package conntrack

import (
	runtimeDebug "runtime/debug"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/memory"
)

var (
	KillerEnabled   bool
	MemoryLimit     uint64
	killerAccess    sync.Mutex
	killerLastCheck time.Time
)

func KillerCheck() error {
	if !KillerEnabled {
		return nil
	}
	killerAccess.Lock()
	now := time.Now()
	if now.Sub(killerLastCheck) < 3*time.Second {
		killerAccess.Unlock()
		return nil
	}
	killerLastCheck = now
	killerAccess.Unlock()
	if memory.Total() > MemoryLimit {
		Close()
		go func() {
			time.Sleep(time.Second)
			runtimeDebug.FreeOSMemory()
		}()
		return E.New("out of memory")
	}
	return nil
}
