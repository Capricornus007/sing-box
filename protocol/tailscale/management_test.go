//go:build with_gvisor

package tailscale

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	adapterEndpoint "github.com/sagernet/sing-box/adapter/endpoint"
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

type managementTestNotificationKey struct {
	identifier string
	typeID     int32
}

type managementTestNotificationStore struct {
	sync.Mutex
	prompts map[managementTestNotificationKey]string
}

type managementTestNotifications struct {
	adapter.PlatformInterface
	entered       chan struct{}
	release       chan struct{}
	cancellations atomic.Int32
	store         *managementTestNotificationStore
}

func (p *managementTestNotifications) UsePlatformNotification() bool { return true }

func (p *managementTestNotifications) SendNotification(notification *adapter.Notification) error {
	if p.store != nil {
		p.store.Lock()
		p.store.prompts[managementTestNotificationKey{notification.Identifier, notification.TypeID}] = notification.OpenURL
		p.store.Unlock()
	}
	close(p.entered)
	if p.release != nil {
		<-p.release
	}
	return nil
}

func (p *managementTestNotifications) CancelNotification(identifier string, typeID int32) error {
	p.cancellations.Add(1)
	if p.store != nil {
		p.store.Lock()
		delete(p.store.prompts, managementTestNotificationKey{identifier, typeID})
		p.store.Unlock()
	}
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
		AuthURL:      "https://example.invalid/login",
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

func TestManagementLateNotificationCancellationPreservesSameTagReplacement(t *testing.T) {
	endpointA, backendA := newExitTestEndpoint(t, "")
	endpointB, _ := newExitTestEndpoint(t, "")
	endpointA.Adapter = adapterEndpoint.NewAdapter("tailscale", "same-tag", nil, nil)
	endpointB.Adapter = adapterEndpoint.NewAdapter("tailscale", "same-tag", nil, nil)
	endpointA.logger = log.NewNOPFactory().Logger()
	endpointB.logger = log.NewNOPFactory().Logger()
	store := &managementTestNotificationStore{prompts: make(map[managementTestNotificationKey]string)}
	platformA := &managementTestNotifications{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		store:   store,
	}
	platformB := &managementTestNotifications{
		entered: make(chan struct{}),
		store:   store,
	}
	endpointA.platformInterface = platformA
	endpointB.platformInterface = platformB
	releaseA := sync.OnceFunc(func() { close(platformA.release) })
	defer releaseA()
	watcherA := &managementTestStateWatcher{status: ipnstate.Status{
		BackendState: ipn.NeedsLogin.String(),
		AuthURL:      "https://example.invalid/login-a",
	}}
	watcherB := &managementTestStateWatcher{status: ipnstate.Status{
		BackendState: ipn.NeedsLogin.String(),
		AuthURL:      "https://example.invalid/login-b",
	}}
	doneA := make(chan struct{})
	go func() { endpointA.watchState(watcherA); close(doneA) }()
	select {
	case <-platformA.entered:
	case <-time.After(time.Second):
		t.Fatal("A did not deliver its notification")
	}
	stoppedA := make(chan struct{})
	go func() {
		// The management and notification portion of Endpoint.Close must not
		// wait for A's SendNotification callback to return.
		endpointA.stopManagement()
		endpointA.cancelAuthNotification()
		close(stoppedA)
	}()
	select {
	case <-stoppedA:
	case <-time.After(time.Second):
		t.Fatal("A shutdown waited on its notification callback")
	}
	doneB := make(chan struct{})
	go func() { endpointB.watchState(watcherB); close(doneB) }()
	select {
	case <-platformB.entered:
	case <-time.After(time.Second):
		t.Fatal("B did not deliver its notification")
	}
	releaseA()
	select {
	case <-doneA:
	case <-time.After(time.Second):
		t.Fatal("A watcher did not finish after late notification return")
	}
	store.Lock()
	promptB := store.prompts[managementTestNotificationKey{endpointB.authNotificationID(), 10}]
	promptCount := len(store.prompts)
	store.Unlock()
	if promptB != watcherB.status.AuthURL || promptCount != 1 {
		t.Fatal("A's late cancellation removed B's same-tag notification")
	}
	if platformA.cancellations.Load() != 2 || backendA.editCount != 0 || endpointA.started.Load() {
		t.Fatal("A did not finish cancellation without mutating or restarting its backend")
	}
	endpointB.stopManagement()
	endpointB.cancelAuthNotification()
	select {
	case <-doneB:
	case <-time.After(time.Second):
		t.Fatal("B watcher did not finish after shutdown")
	}
	store.Lock()
	remaining := len(store.prompts)
	store.Unlock()
	if remaining != 0 {
		t.Fatal("B shutdown did not cancel its own notification")
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
