//go:build with_tailscale

package tailscale

import (
	"context"
	"net/netip"

	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnlocal"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
)

type tailscaleManagementClient interface {
	Ping(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error)
	Logout(context.Context) error
}

type tailscaleStateWatcher interface {
	StatusWithoutPeers() *ipnstate.Status
	WatchNotifications(context.Context, ipn.NotifyWatchOpt, func(), func(*ipn.Notify) bool)
}

func (t *Endpoint) stopManagement() bool {
	if t.cancel != nil {
		t.cancel()
	}
	t.managementAccess.Lock()
	if t.closed {
		t.managementAccess.Unlock()
		return false
	}
	t.closed = true
	t.started.Store(false)
	t.exitGeneration++
	t.exitChange = nil
	t.managementAccess.Unlock()
	return true
}

// managementContext captures an initialized backend and links caller cancellation
// to endpoint shutdown. It never starts a server or waits for a foreign callback.
func (t *Endpoint) managementContext(ctx context.Context) (context.Context, context.CancelFunc, *ipnlocal.LocalBackend, error) {
	t.managementAccess.Lock()
	defer t.managementAccess.Unlock()
	if err := t.checkManagementLocked(ctx); err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(t.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}, t.localBackend.Load(), nil
}
