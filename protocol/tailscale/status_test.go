//go:build with_gvisor

package tailscale

import (
	"net/netip"
	"testing"

	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
)

func TestTailscaleStatusCurrentExitUsesPreferencesAndLivePeers(t *testing.T) {
	peer := exitTestPeer("A", "100.64.0.1")
	peer.ExitNode = true
	status := &ipnstate.Status{
		Peer: exitTestPeers(peer, nil),
		ExitNodeStatus: &ipnstate.ExitNodeStatus{
			ID: "stale",
		},
	}
	for _, test := range []struct {
		name string
		prefs ipn.Prefs
		wantID string
		wantIP string
		live bool
	}{
		{name: "cleared"},
		{name: "selected", prefs: ipn.Prefs{ExitNodeID: "A"}, wantID: "A", live: true},
		{name: "unavailable", prefs: ipn.Prefs{ExitNodeID: "removed"}, wantID: "removed"},
		{name: "unresolved-ip", prefs: ipn.Prefs{ExitNodeIP: netip.MustParseAddr("100.64.0.3")}, wantIP: "100.64.0.3"},
		{name: "live-ip", prefs: ipn.Prefs{ExitNodeIP: netip.MustParseAddr("100.64.0.1")}, wantIP: "100.64.0.1", live: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := convertTailscaleStatus(status)
			setSelectedExitNode(result, test.prefs.View())
			if result.SelectedExitNodeID != test.wantID || result.SelectedExitNodeIP != test.wantIP {
				t.Fatalf("selected = %q/%q", result.SelectedExitNodeID, result.SelectedExitNodeIP)
			}
			if (result.ExitNode != nil) != test.live {
				t.Fatalf("live exit = %+v, want live %v", result.ExitNode, test.live)
			}
		})
	}
	status.Peer = nil
	result := convertTailscaleStatus(status)
	setSelectedExitNode(result, (&ipn.Prefs{ExitNodeID: "A"}).View())
	if result.ExitNode != nil || result.SelectedExitNodeID != "A" {
		t.Fatal("cached exit snapshot replaced unavailable selection")
	}
}
