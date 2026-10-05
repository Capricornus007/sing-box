//go:build with_tailscale

package tailscale

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
)

var _ adapter.TailscaleEndpoint = (*Endpoint)(nil)

// The callback must return promptly. Subscription return joins its collectors;
// endpoint shutdown cancels them without waiting on the subscriber.
func (t *Endpoint) SubscribeTailscaleStatus(ctx context.Context, fn func(*adapter.TailscaleEndpointStatus)) error {
	ctx, cancel, localBackend, err := t.managementContext(ctx)
	if err != nil {
		return err
	}
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	// The notification callback must stay cheap and non-blocking: a
	// watcher whose queue fills is disconnected by the IPN bus, so
	// status collection and delivery (which blocks on the subscriber)
	// run on a separate coalescing goroutine.
	updateSignal := make(chan struct{}, 1)
	scheduleUpdate := func() {
		select {
		case updateSignal <- struct{}{}:
		default:
		}
	}
	workers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-updateSignal:
			}
			t.managementAccess.Lock()
			if t.checkManagementLocked(ctx) != nil {
				t.managementAccess.Unlock()
				return
			}
			status := localBackend.Status()
			result := convertTailscaleStatus(status)
			setSelectedExitNode(result, localBackend.Prefs())
			result.KeyAuth = t.keyAuth
			canShareFiles, taildropTargets := t.taildropTargets()
			result.CanShareFiles = canShareFiles
			result.WaitingFileCount = t.taildrop.waitingFileCount()
			result.ReceivingFileCount = t.taildrop.receivingFileCount()
			result.UnreadFileCount = t.taildrop.unreadFileCount()
			result.CertDomains = t.server.CertDomains()
			if len(taildropTargets) > 0 {
				for _, group := range result.UserGroups {
					for _, peer := range group.Peers {
						peer.CanReceiveFiles = taildropTargets[peer.StableID]
					}
				}
			}
			t.managementAccess.Unlock()
			if ctx.Err() != nil {
				return
			}
			fn(result)
		}
	})
	fileSignal := make(chan struct{}, 1)
	watchErr := t.taildrop.watch(t.taildrop.fileWatchers, fileSignal)
	if watchErr == nil {
		defer t.taildrop.unwatch(t.taildrop.fileWatchers, fileSignal)
		workers.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-fileSignal:
					scheduleUpdate()
				}
			}
		})
	}
	scheduleUpdate()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var busError string
		localBackend.WatchNotifications(ctx, ipn.NotifyInitialState|ipn.NotifyPeerPatches, nil, func(roNotify *ipn.Notify) (keepGoing bool) {
			if roNotify.ErrMessage != nil {
				busError = *roNotify.ErrMessage
				return false
			}
			if roNotify.State != nil || roNotify.SelfChange != nil ||
				len(roNotify.PeersChanged) > 0 || len(roNotify.PeersRemoved) > 0 || len(roNotify.PeerChangedPatch) > 0 ||
				roNotify.BrowseToURL != nil || roNotify.Prefs != nil {
				scheduleUpdate()
			}
			return true
		})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if busError != "" {
			t.logger.Warn("restarting status watcher: ", busError)
		} else {
			t.logger.Warn("status watcher stopped unexpectedly, restarting")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		scheduleUpdate()
	}
}

func convertTailscaleStatus(status *ipnstate.Status) *adapter.TailscaleEndpointStatus {
	result := &adapter.TailscaleEndpointStatus{
		BackendState: status.BackendState,
		AuthURL:      status.AuthURL,
	}
	if status.CurrentTailnet != nil {
		result.NetworkName = status.CurrentTailnet.Name
		result.MagicDNSSuffix = status.CurrentTailnet.MagicDNSSuffix
	}
	if status.Self != nil {
		result.Self = convertTailscalePeer(status.Self)
	}
	groupIndex := make(map[int64]*adapter.TailscaleUserGroup)
	for _, peerKey := range status.Peers() {
		peer := status.Peer[peerKey]
		if peer == nil {
			continue
		}
		userID := int64(peer.UserID)
		group, loaded := groupIndex[userID]
		if !loaded {
			group = &adapter.TailscaleUserGroup{
				UserID: userID,
			}
			if profile, hasProfile := status.User[peer.UserID]; hasProfile {
				group.LoginName = profile.LoginName
				group.DisplayName = profile.DisplayName
				group.ProfilePicURL = profile.ProfilePicURL
			}
			groupIndex[userID] = group
			result.UserGroups = append(result.UserGroups, group)
		}
		group.Peers = append(group.Peers, convertTailscalePeer(peer))
	}
	for _, group := range result.UserGroups {
		slices.SortStableFunc(group.Peers, func(a, b *adapter.TailscalePeer) int {
			if a.Online != b.Online {
				if a.Online {
					return -1
				}
				return 1
			}
			return 0
		})
	}
	return result
}

// Preferences identify the selection even when its peer is absent. Only live
// peer flags confirm it; cached ExitNodeStatus can survive a clear or removal.
func setSelectedExitNode(result *adapter.TailscaleEndpointStatus, prefs ipn.PrefsView) {
	result.ExitNode = nil
	result.SelectedExitNodeID = ""
	result.SelectedExitNodeIP = ""
	if !prefs.Valid() {
		return
	}
	result.SelectedExitNodeID = string(prefs.ExitNodeID())
	if prefs.ExitNodeIP().IsValid() {
		result.SelectedExitNodeIP = prefs.ExitNodeIP().String()
	}
	for _, group := range result.UserGroups {
		for _, peer := range group.Peers {
			selected := result.SelectedExitNodeID != "" && peer.StableID == result.SelectedExitNodeID
			if result.SelectedExitNodeID == "" && result.SelectedExitNodeIP != "" {
				selected = slices.Contains(peer.TailscaleIPs, result.SelectedExitNodeIP)
			}
			if selected && peer.ExitNode {
				result.ExitNode = peer
			}
		}
	}
}

func convertTailscalePeer(peer *ipnstate.PeerStatus) *adapter.TailscalePeer {
	ips := make([]string, len(peer.TailscaleIPs))
	for i, ip := range peer.TailscaleIPs {
		ips[i] = ip.String()
	}
	var keyExpiry int64
	if peer.KeyExpiry != nil {
		keyExpiry = peer.KeyExpiry.Unix()
	}
	var lastSeen int64
	if !peer.LastSeen.IsZero() {
		lastSeen = peer.LastSeen.Unix()
	}
	return &adapter.TailscalePeer{
		StableID:       string(peer.ID),
		HostName:       peer.HostName,
		DNSName:        peer.DNSName,
		OS:             peer.OS,
		TailscaleIPs:   ips,
		SSHHostKeys:    peer.SSH_HostKeys,
		Online:         peer.Online,
		ExitNode:       peer.ExitNode,
		ExitNodeOption: peer.ExitNodeOption,
		ShareeNode:     peer.ShareeNode,
		Expired:        peer.Expired,
		Active:         peer.Active,
		RxBytes:        peer.RxBytes,
		TxBytes:        peer.TxBytes,
		UserID:         int64(peer.UserID),
		KeyExpiry:      keyExpiry,
		LastSeen:       lastSeen,
	}
}
