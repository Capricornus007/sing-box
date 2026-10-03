//go:build with_gvisor

package tailscale

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
)

type managementTestPinger struct {
	ping func(context.Context) (*ipnstate.PingResult, error)
}

func (p *managementTestPinger) Ping(ctx context.Context, _ netip.Addr, kind tailcfg.PingType) (*ipnstate.PingResult, error) {
	if kind != tailcfg.PingDisco {
		panic("unexpected ping type")
	}
	return p.ping(ctx)
}

func (p *managementTestPinger) Logout(context.Context) error {
	return nil
}

type managementTestStateWatcher struct {
	status ipnstate.Status
}

func (w *managementTestStateWatcher) StatusWithoutPeers() *ipnstate.Status {
	return &w.status
}

func (w *managementTestStateWatcher) WatchNotifications(ctx context.Context, _ ipn.NotifyWatchOpt, _ func(), fn func(*ipn.Notify) bool) {
	state := ipn.NeedsLogin
	if fn(&ipn.Notify{State: &state}) {
		<-ctx.Done()
	}
	// A queued Running notification arriving after cancellation must be ignored.
	state = ipn.Running
	fn(&ipn.Notify{State: &state})
}

type managementTestNotifications struct {
	adapter.PlatformInterface
	entered chan struct{}
	release chan struct{}
	cancellations atomic.Int32
}

func (p *managementTestNotifications) UsePlatformNotification() bool { return true }

func (p *managementTestNotifications) SendNotification(*adapter.Notification) error {
	close(p.entered)
	<-p.release
	return nil
}

func (p *managementTestNotifications) CancelNotification(string, int32) error {
	p.cancellations.Add(1)
	return nil
}

func TestManagementCloseDoesNotWaitForNotificationCallback(t *testing.T) {
	endpoint, backend := newExitTestEndpoint(t, "100.64.0.2")
	endpoint.logger = log.NewNOPFactory().Logger()
	platform := &managementTestNotifications{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	endpoint.platformInterface = platform
	watcher := &managementTestStateWatcher{status: ipnstate.Status{
		BackendState: ipn.NeedsLogin.String(),
		AuthURL: "https://example.invalid/login",
	}}
	done := make(chan struct{})
	go func() { endpoint.watchState(watcher); close(done) }()
	<-platform.entered
	stopped := make(chan struct{})
	go func() { endpoint.stopManagement(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		close(platform.release)
		t.Fatal("management teardown waited on notification callback")
	}
	endpoint.cancelAuthNotification()
	close(platform.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state watcher did not exit after callback returned")
	}
	if backend.editCount != 0 || endpoint.started.Load() {
		t.Fatal("late notification return mutated or restarted the endpoint")
	}
	if platform.cancellations.Load() != 2 {
		t.Fatal("late notification was not cancelled again after delivery")
	}
}

func TestManagementRejectsNotStartedAndClosedWithoutServer(t *testing.T) {
	for _, state := range []string{"not-started", "failed-start", "closed"} {
		t.Run(state, func(t *testing.T) {
			endpoint, _ := newExitTestEndpoint(t, "")
			endpoint.started.Store(false)
			if state == "not-started" {
				endpoint.managementBackend = nil
			}
			prefix := "tailscale:not-running"
			if state == "closed" {
				endpoint.stopManagement()
				prefix = "tailscale:closed"
			}
			// No tsnet server exists: any lazy accessor would panic or start it.
			for _, err := range []error{
				endpoint.SetTailscaleExitNode(context.Background(), ""),
				endpoint.SubscribeTailscaleStatus(context.Background(), func(*adapter.TailscaleEndpointStatus) { t.Error("unexpected status") }),
				endpoint.StartTailscalePing(context.Background(), "100.64.0.2", func(*adapter.TailscalePingResult) { t.Error("unexpected ping") }),
				endpoint.Logout(context.Background()),
			} {
				if err == nil || !strings.HasPrefix(err.Error(), prefix) {
					t.Fatalf("%s: %v", prefix, err)
				}
			}
		})
	}
}

func TestManagementContextCancellation(t *testing.T) {
	for _, source := range []string{"caller", "endpoint"} {
		t.Run(source, func(t *testing.T) {
			endpoint, _ := newExitTestEndpoint(t, "")
			caller, cancelCaller := context.WithCancel(context.Background())
			defer cancelCaller()
			ctx, cancel, _, err := endpoint.managementContext(caller)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			if source == "caller" {
				cancelCaller()
			} else {
				endpoint.stopManagement()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("operation lifetime not cancelled")
			}
		})
	}
}

func TestTailscalePingCancellation(t *testing.T) {
	for _, source := range []string{"caller", "endpoint"} {
		t.Run(source, func(t *testing.T) {
			endpoint, _ := newExitTestEndpoint(t, "")
			entered := make(chan struct{})
			endpoint.managementClient = &managementTestPinger{ping: func(ctx context.Context) (*ipnstate.PingResult, error) {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- endpoint.StartTailscalePing(ctx, "100.64.0.2", func(*adapter.TailscalePingResult) { t.Error("sample after cancellation") })
			}()
			<-entered
			if source == "caller" {
				cancel()
			} else {
				endpoint.stopManagement()
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("ping returned %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("ping did not return after cancellation")
			}
		})
	}
}

func TestManagementCloseDoesNotWaitForPingCallback(t *testing.T) {
	endpoint, _ := newExitTestEndpoint(t, "")
	endpoint.managementClient = &managementTestPinger{ping: func(context.Context) (*ipnstate.PingResult, error) {
		return &ipnstate.PingResult{LatencySeconds: 0.01}, nil
	}}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- endpoint.StartTailscalePing(context.Background(), "100.64.0.2", func(*adapter.TailscalePingResult) {
			close(entered)
			<-release
		})
	}()
	<-entered
	stopped := make(chan struct{})
	go func() { endpoint.stopManagement(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("endpoint shutdown waited on a foreign callback")
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ping returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ping did not finish after callback returned")
	}
	if endpoint.stopManagement() {
		t.Fatal("repeated shutdown was not idempotent")
	}
}
