//go:build with_gvisor

package tailscale

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"
)

type exitTestBackend struct {
	prefs       ipn.Prefs
	status      ipnstate.Status
	editErr     error
	statusHook  func()
	editCount   int
}

func (b *exitTestBackend) Status() *ipnstate.Status {
	if b.statusHook != nil {
		b.statusHook()
	}
	return &b.status
}

func (b *exitTestBackend) Prefs() ipn.PrefsView {
	return b.prefs.Clone().View()
}

func (b *exitTestBackend) EditPrefs(prefs *ipn.MaskedPrefs) (ipn.PrefsView, error) {
	b.editCount++
	if b.editErr != nil {
		return ipn.PrefsView{}, b.editErr
	}
	b.prefs.ApplyEdits(prefs)
	return b.Prefs(), nil
}

func exitTestPeer(id, address string) *ipnstate.PeerStatus {
	return &ipnstate.PeerStatus{
		ID:             tailcfg.StableNodeID(id),
		DNSName:        id + ".example.ts.net.",
		ExitNodeOption: true,
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr(address)},
	}
}

func exitTestPeers(peers ...*ipnstate.PeerStatus) map[key.NodePublic]*ipnstate.PeerStatus {
	result := make(map[key.NodePublic]*ipnstate.PeerStatus)
	for _, peer := range peers {
		result[key.NewNode().Public()] = peer
	}
	return result
}

func newExitTestEndpoint(t *testing.T, desired string) (*Endpoint, *exitTestBackend) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	backend := &exitTestBackend{
		status: ipnstate.Status{
			BackendState: ipn.Running.String(),
			Peer: exitTestPeers(exitTestPeer("B", "100.64.0.2")),
		},
	}
	endpoint := &Endpoint{
		ctx:               ctx,
		cancel:            cancel,
		managementBackend: backend,
		exitNode:          desired,
		exitNodePending:   desired != "",
	}
	endpoint.started.Store(true)
	t.Cleanup(func() { endpoint.stopManagement() })
	return endpoint, backend
}

func TestExitNodePendingCannotReplaceLiveChange(t *testing.T) {
	for _, choice := range []string{"B", ""} {
		t.Run("choice="+choice, func(t *testing.T) {
			endpoint, backend := newExitTestEndpoint(t, "100.64.0.1")
			if err := endpoint.applyExitNode(); err == nil {
				t.Fatal("missing initial peer unexpectedly resolved")
			}
			if err := endpoint.SetTailscaleExitNode(context.Background(), choice); err != nil {
				t.Fatal(err)
			}
			backend.status.Peer = exitTestPeers(exitTestPeer("A", "100.64.0.1"), exitTestPeer("B", "100.64.0.2"))
			if err := endpoint.applyExitNode(); err != nil {
				t.Fatal(err)
			}
			if got := string(backend.prefs.ExitNodeID); got != choice {
				t.Fatalf("late peer replaced %q with %q", choice, got)
			}
			// Reauthentication must use the live intent, never the constructor value.
			backend.prefs.ExitNodeID = ""
			endpoint.resetExitNodePending()
			if err := endpoint.applyExitNode(); err != nil {
				t.Fatal(err)
			}
			if got := string(backend.prefs.ExitNodeID); got != choice {
				t.Fatalf("reauth selected %q, want %q", got, choice)
			}
		})
	}
}

func TestExitNodeWatcherAndChangeSerialize(t *testing.T) {
	for _, choice := range []string{"B", ""} {
		t.Run("choice="+choice, func(t *testing.T) {
			endpoint, backend := newExitTestEndpoint(t, "100.64.0.1")
			backend.status.Peer = exitTestPeers(exitTestPeer("A", "100.64.0.1"), exitTestPeer("B", "100.64.0.2"))
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			backend.statusHook = func() { once.Do(func() { close(entered); <-release }) }
			applied := make(chan error, 1)
			go func() { applied <- endpoint.applyExitNode() }()
			<-entered
			changed := make(chan error, 1)
			go func() { changed <- endpoint.SetTailscaleExitNode(context.Background(), choice) }()
			close(release)
			if err := <-applied; err != nil {
				t.Fatal(err)
			}
			if err := <-changed; err != nil {
				t.Fatal(err)
			}
			endpoint.resetExitNodePending()
			if err := endpoint.applyExitNode(); err != nil {
				t.Fatal(err)
			}
			if string(backend.prefs.ExitNodeID) != choice {
				t.Fatalf("stale watcher selected %q", backend.prefs.ExitNodeID)
			}
		})
	}
}

func TestExitNodeRollbackRestoresOnlyExitState(t *testing.T) {
	for _, state := range []string{"selected", "unresolved", "empty", "unresolved-ip"} {
		t.Run(state, func(t *testing.T) {
			endpoint, backend := newExitTestEndpoint(t, "unresolved-A")
			switch state {
			case "selected":
				endpoint.exitNode = "100.64.0.1"
				endpoint.exitNodeID = "A"
				endpoint.exitNodePending = false
				backend.prefs.ExitNodeID = "A"
			case "empty":
				endpoint.exitNode = ""
				endpoint.exitNodePending = false
			case "unresolved-ip":
				backend.prefs.ExitNodeIP = netip.MustParseAddr("100.64.0.1")
			}
			backend.prefs.ExitNodeAllowLANAccess = true
			endpoint.exitNodeAllowLANAccess = true
			before := readExitNodePrefs(backend.Prefs())
			desired, stableID := endpoint.exitNode, endpoint.exitNodeID
			change, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "B")
			if err != nil {
				t.Fatal(err)
			}
			backend.prefs.Hostname = "unrelated-update"
			backend.prefs.RouteAll = true
			backend.status.Peer = nil // Undo must not resolve either peer.
			if err := change.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := readExitNodePrefs(backend.Prefs()); got != before {
				t.Fatalf("exit prefs = %+v, want %+v", got, before)
			}
			if endpoint.exitNode != desired || endpoint.exitNodeID != stableID || endpoint.exitNodePending != (desired != "") {
				t.Fatalf("desired state not restored: %q %q %v", endpoint.exitNode, endpoint.exitNodeID, endpoint.exitNodePending)
			}
			if backend.prefs.Hostname != "unrelated-update" || !backend.prefs.RouteAll {
				t.Fatal("rollback overwrote unrelated preferences")
			}
			if err := change.Rollback(context.Background()); err != nil {
				t.Fatal("repeated rollback:", err)
			}
			if err := change.Commit(); err == nil {
				t.Fatal("commit after rollback succeeded")
			}
		})
	}
}

func TestExitNodeValidationBeforeMutation(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	for _, test := range []struct {
		name string
		edit func(*ipnstate.PeerStatus)
	}{
		{"unapproved", func(peer *ipnstate.PeerStatus) { peer.ExitNodeOption = false }},
		{"expired", func(peer *ipnstate.PeerStatus) { peer.Expired = true }},
		{"key-expired", func(peer *ipnstate.PeerStatus) { peer.KeyExpiry = &past }},
		{"no-address", func(peer *ipnstate.PeerStatus) { peer.TailscaleIPs = nil }},
		{"not-tailscale", func(peer *ipnstate.PeerStatus) { peer.TailscaleIPs = []netip.Addr{netip.MustParseAddr("192.0.2.1")} }},
		{"missing", func(peer *ipnstate.PeerStatus) { peer.ID = "other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint, backend := newExitTestEndpoint(t, "unresolved-A")
			peer := exitTestPeer("B", "100.64.0.2")
			test.edit(peer)
			backend.status.Peer = exitTestPeers(peer, nil)
			before := backend.prefs.Clone()
			if _, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "B"); err == nil {
				t.Fatal("invalid selection accepted")
			}
			if !reflect.DeepEqual(before, &backend.prefs) || backend.editCount != 0 || endpoint.exitNode != "unresolved-A" || !endpoint.exitNodePending {
				t.Fatal("invalid selection mutated state")
			}
		})
	}
}

func TestExitNodeCanonicalAddressAndOfflineChoice(t *testing.T) {
	for _, addresses := range [][]string{
		{"fd7a:115c:a1e0::2", "100.64.0.2"},
		{"fd7a:115c:a1e0::2"},
	} {
		endpoint, backend := newExitTestEndpoint(t, "")
		peer := exitTestPeer("B", addresses[0])
		peer.TailscaleIPs = nil
		for _, address := range addresses {
			peer.TailscaleIPs = append(peer.TailscaleIPs, netip.MustParseAddr(address))
		}
		backend.status.Peer = exitTestPeers(peer)
		change, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "B")
		if err != nil {
			t.Fatal("offline flag must not reject explicit selection:", err)
		}
		if want := addresses[len(addresses)-1]; change.SavedValue() != want {
			t.Fatalf("saved = %q, want %q", change.SavedValue(), want)
		}
		if err := change.Commit(); err != nil {
			t.Fatal(err)
		}
		peer.DNSName = "renamed.example.ts.net."
		endpoint.resetExitNodePending()
		if err := endpoint.applyExitNode(); err != nil || backend.prefs.ExitNodeID != "B" {
			t.Fatalf("rename redirected pinned identity: %v", err)
		}
	}
}

func TestExitNodeFinalizationAndFailures(t *testing.T) {
	endpoint, backend := newExitTestEndpoint(t, "unresolved-A")
	backend.editErr = errors.New("write rejected")
	if _, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "B"); err == nil {
		t.Fatal("write failure ignored")
	}
	if endpoint.exitChange != nil || endpoint.exitNode != "unresolved-A" || !endpoint.exitNodePending {
		t.Fatal("failed write changed desired state")
	}
	backend.editErr = nil
	change, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "B")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), ""); err == nil || !strings.HasPrefix(err.Error(), "tailscale:busy") {
		t.Fatalf("concurrent change not rejected: %v", err)
	}
	backend.editErr = errors.New("undo rejected")
	if err := change.Rollback(context.Background()); err == nil {
		t.Fatal("undo failure ignored")
	}
	if endpoint.exitChange != change || endpoint.exitNode != "100.64.0.2" {
		t.Fatal("failed undo lost ownership")
	}
	backend.editErr = nil
	if err := change.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := change.Commit(); err != nil {
		t.Fatal("repeated commit:", err)
	}
	if err := change.Rollback(context.Background()); err == nil {
		t.Fatal("rollback after commit succeeded")
	}
	if err := endpoint.SetTailscaleExitNode(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if backend.prefs.ExitNodeID != "" || backend.prefs.ExitNodeIP.IsValid() || endpoint.exitNodePending {
		t.Fatal("clear retained an exit selector or pending retry")
	}
}

func TestExitNodeCancellationAndClose(t *testing.T) {
	endpoint, backend := newExitTestEndpoint(t, "A")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := endpoint.BeginTailscaleExitNodeChange(ctx, "B"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled apply: %v", err)
	}
	if backend.editCount != 0 {
		t.Fatal("cancelled apply wrote preferences")
	}
	change, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "B")
	if err != nil {
		t.Fatal(err)
	}
	if err := change.Rollback(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled undo: %v", err)
	}
	endpoint.stopManagement()
	for _, err := range []error{change.Commit(), change.Rollback(context.Background()), endpoint.SetTailscaleExitNode(context.Background(), "")} {
		if err == nil || !strings.HasPrefix(err.Error(), "tailscale:closed") {
			t.Fatalf("closed operation returned %v", err)
		}
	}
	if backend.editCount != 1 {
		t.Fatal("closed operation wrote preferences")
	}
}

func TestExitNodeRollbackClearDuringReauth(t *testing.T) {
	endpoint, backend := newExitTestEndpoint(t, "100.64.0.1")
	endpoint.exitNodeID = "A"
	endpoint.exitNodePending = false
	backend.prefs.ExitNodeID = "A"
	change, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if change.SavedValue() != "" {
		t.Fatal("clear has a nonempty saved value")
	}
	backend.status.BackendState = ipn.NeedsLogin.String()
	endpoint.resetExitNodePending()
	if err := change.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !endpoint.exitNodePending || backend.prefs.ExitNodeID != "A" {
		t.Fatal("undo after reauth did not restore pending selection")
	}
	backend.status.BackendState = ipn.Running.String()
	backend.status.Peer = exitTestPeers(exitTestPeer("A", "100.64.0.1"))
	if err := endpoint.applyExitNode(); err != nil {
		t.Fatal(err)
	}
	if backend.prefs.ExitNodeID != "A" || endpoint.exitNodePending {
		t.Fatal("restored selection did not converge")
	}
}

func TestExitNodeCancellationDuringResolution(t *testing.T) {
	endpoint, backend := newExitTestEndpoint(t, "unresolved-A")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend.statusHook = cancel
	if _, err := endpoint.BeginTailscaleExitNodeChange(ctx, "B"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel during resolution returned %v", err)
	}
	if backend.editCount != 0 || endpoint.exitNode != "unresolved-A" || !endpoint.exitNodePending {
		t.Fatal("cancel during resolution mutated exit state")
	}
}

func TestExitNodeAdvertiseConflict(t *testing.T) {
	endpoint, backend := newExitTestEndpoint(t, "")
	endpoint.advertiseExitNode = true
	if _, err := endpoint.BeginTailscaleExitNodeChange(context.Background(), "B"); err == nil {
		t.Fatal("advertise/use conflict accepted")
	}
	if backend.editCount != 0 {
		t.Fatal("conflict changed preferences")
	}
	if err := endpoint.SetTailscaleExitNode(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}
