//go:build with_gvisor

package tailscale

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/net/tsaddr"
	"github.com/sagernet/tailscale/tailcfg"
)

// These backend operations are local and serialized by managementAccess, never
// made through the lazy tsnet LocalClient accessor.
type exitNodeBackend interface {
	Status() *ipnstate.Status
	Prefs() ipn.PrefsView
	EditPrefs(*ipn.MaskedPrefs) (ipn.PrefsView, error)
}

type exitNodePrefs struct {
	id       tailcfg.StableNodeID
	ip       netip.Addr
	allowLAN bool
	auto     ipn.ExitNodeExpression
}

func readExitNodePrefs(p ipn.PrefsView) exitNodePrefs {
	return exitNodePrefs{p.ExitNodeID(), p.ExitNodeIP(), p.ExitNodeAllowLANAccess(), p.AutoExitNode()}
}

func (p exitNodePrefs) mask() *ipn.MaskedPrefs {
	return &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ExitNodeID:             p.id,
			ExitNodeIP:             p.ip,
			ExitNodeAllowLANAccess: p.allowLAN,
			AutoExitNode:           p.auto,
		},
		ExitNodeIDSet:             true,
		ExitNodeIPSet:             true,
		ExitNodeAllowLANAccessSet: true,
		AutoExitNodeSet:           true,
	}
}

// ExitNodeChange owns one applied exit selection until Commit or Rollback.
// It snapshots only exit preferences; unrelated backend preferences are retained.
type ExitNodeChange struct {
	endpoint   *Endpoint
	savedValue string
	generation uint64
	before     exitNodePrefs
	desired    string
	stableID   string
	pending    bool
	committed  bool
	rolledBack bool
}

func (c *ExitNodeChange) SavedValue() string {
	return c.savedValue
}

func (t *Endpoint) checkManagementLocked(ctx context.Context) error {
	if t.closed || (t.ctx != nil && t.ctx.Err() != nil) {
		return fmt.Errorf("tailscale:closed")
	}
	if !t.started.Load() || t.managementBackend == nil {
		return fmt.Errorf("tailscale:not-running")
	}
	return ctx.Err()
}

func (t *Endpoint) BeginTailscaleExitNodeChange(ctx context.Context, stableID string) (*ExitNodeChange, error) {
	t.managementAccess.Lock()
	defer t.managementAccess.Unlock()
	if err := t.checkManagementLocked(ctx); err != nil {
		return nil, err
	}
	if t.exitChange != nil {
		return nil, fmt.Errorf("tailscale:busy: exit change awaiting finalization")
	}
	if t.advertiseExitNode && stableID != "" {
		return nil, fmt.Errorf("cannot advertise an exit node and use an exit node at the same time")
	}
	var savedValue string
	if stableID != "" {
		ip, err := exitNodeAddress(t.managementBackend.Status(), stableID, time.Now())
		if err != nil {
			return nil, err
		}
		savedValue = ip.String()
	}
	if err := t.checkManagementLocked(ctx); err != nil {
		return nil, err
	}
	prefs := t.managementBackend.Prefs()
	if !prefs.Valid() {
		return nil, fmt.Errorf("tailscale:not-running: no preferences")
	}
	change := &ExitNodeChange{
		endpoint:   t,
		savedValue: savedValue,
		before:     readExitNodePrefs(prefs),
		desired:    t.exitNode,
		stableID:   t.exitNodeID,
		pending:    t.exitNodePending,
	}
	selection := exitNodePrefs{id: tailcfg.StableNodeID(stableID), allowLAN: t.exitNodeAllowLANAccess}
	if err := t.checkManagementLocked(ctx); err != nil {
		return nil, err
	}
	applied, err := t.managementBackend.EditPrefs(selection.mask())
	if err != nil {
		return nil, err
	}
	if !applied.Valid() || readExitNodePrefs(applied) != selection {
		restored, restoreErr := t.managementBackend.EditPrefs(change.before.mask())
		if restoreErr != nil || !restored.Valid() || readExitNodePrefs(restored) != change.before {
			return nil, fmt.Errorf("tailscale:conflict: exit preferences diverged after backend reconciliation: %v", restoreErr)
		}
		return nil, fmt.Errorf("tailscale:conflict: backend rejected the requested exit selection")
	}
	t.exitNode = savedValue
	t.exitNodeID = stableID
	t.exitNodePending = false
	t.exitGeneration++
	change.generation = t.exitGeneration
	t.exitChange = change
	return change, nil
}

func (t *Endpoint) SetTailscaleExitNode(ctx context.Context, stableID string) error {
	change, err := t.BeginTailscaleExitNodeChange(ctx, stableID)
	if err != nil {
		return err
	}
	return change.Commit()
}

func (c *ExitNodeChange) Commit() error {
	t := c.endpoint
	t.managementAccess.Lock()
	defer t.managementAccess.Unlock()
	if err := t.checkManagementLocked(context.Background()); err != nil {
		return err
	}
	if c.committed {
		return nil
	}
	if c.rolledBack || t.exitChange != c || t.exitGeneration != c.generation {
		return fmt.Errorf("tailscale:conflict: exit change is no longer current")
	}
	c.committed = true
	t.exitChange = nil
	return nil
}

func (c *ExitNodeChange) Rollback(ctx context.Context) error {
	t := c.endpoint
	t.managementAccess.Lock()
	defer t.managementAccess.Unlock()
	if err := t.checkManagementLocked(ctx); err != nil {
		return err
	}
	if c.rolledBack {
		return nil
	}
	if c.committed || t.exitChange != c || t.exitGeneration != c.generation {
		return fmt.Errorf("tailscale:conflict: exit change is no longer current")
	}
	// Do not resolve or validate the old peer: it may have disappeared, or the
	// old configured name may never have resolved in the first place.
	prefs, err := t.managementBackend.EditPrefs(c.before.mask())
	if err != nil {
		return err
	}
	if !prefs.Valid() || readExitNodePrefs(prefs) != c.before {
		return fmt.Errorf("tailscale:conflict: backend did not restore exact exit preferences")
	}
	t.exitNode = c.desired
	t.exitNodeID = c.stableID
	t.exitNodePending = c.pending
	if c.desired != "" {
		status := t.managementBackend.Status()
		_, peerErr := exitNodeAddress(status, c.stableID, time.Now())
		if status.BackendState != ipn.Running.String() || peerErr != nil {
			t.exitNodePending = true
		}
	}
	t.exitGeneration++
	t.exitChange = nil
	c.rolledBack = true
	return nil
}

func exitNodeAddress(status *ipnstate.Status, stableID string, now time.Time) (netip.Addr, error) {
	for _, peer := range status.Peer {
		if peer == nil || string(peer.ID) != stableID {
			continue
		}
		if !peer.ExitNodeOption || peer.Expired || (peer.KeyExpiry != nil && peer.KeyExpiry.Unix() > 0 && !peer.KeyExpiry.After(now)) {
			return netip.Addr{}, fmt.Errorf("tailscale:invalid-peer: exit node is unapproved or expired")
		}
		var selected netip.Addr
		for _, address := range peer.TailscaleIPs {
			address = address.Unmap()
			if address.Zone() != "" || !tsaddr.IsTailscaleIP(address) {
				continue
			}
			if !selected.IsValid() || (address.Is4() && selected.Is6()) || (address.Is4() == selected.Is4() && address.Less(selected)) {
				selected = address
			}
		}
		if selected.IsValid() {
			return selected, nil
		}
		return netip.Addr{}, fmt.Errorf("tailscale:invalid-peer: exit node has no Tailscale address")
	}
	return netip.Addr{}, fmt.Errorf("tailscale:invalid-peer: exit node not found")
}

func (t *Endpoint) resetExitNodePending() {
	t.managementAccess.Lock()
	defer t.managementAccess.Unlock()
	if t.closed || t.ctx.Err() != nil {
		return
	}
	t.exitNodePending = t.exitNode != ""
}

func (t *Endpoint) applyExitNode() error {
	t.managementAccess.Lock()
	defer t.managementAccess.Unlock()
	if err := t.checkManagementLocked(t.ctx); err != nil {
		return err
	}
	if !t.exitNodePending {
		return nil
	}
	status := t.managementBackend.Status()
	stableID := t.exitNodeID
	if stableID == "" {
		prefs := new(ipn.Prefs)
		if err := prefs.SetExitNodeIP(t.exitNode, status); err != nil {
			return err
		}
		for _, peer := range status.Peer {
			if peer == nil {
				continue
			}
			for _, address := range peer.TailscaleIPs {
				if address == prefs.ExitNodeIP {
					stableID = string(peer.ID)
				}
			}
		}
	}
	if _, err := exitNodeAddress(status, stableID, time.Now()); err != nil {
		return err
	}
	if err := t.checkManagementLocked(t.ctx); err != nil {
		return err
	}
	selection := exitNodePrefs{id: tailcfg.StableNodeID(stableID), allowLAN: t.exitNodeAllowLANAccess}
	prefs, err := t.managementBackend.EditPrefs(selection.mask())
	if err != nil {
		return err
	}
	if !prefs.Valid() || readExitNodePrefs(prefs) != selection {
		return fmt.Errorf("tailscale:conflict: backend rejected the pending exit selection")
	}
	t.exitNodeID = stableID
	t.exitNodePending = false
	return nil
}
