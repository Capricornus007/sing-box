//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
)

// bypassIPSet 取代 mihomo 的全域 resolver.EBFPBypassIPSet：我方樹沒有那個 DNS 中介層入口，
// 但 fake-ip 仍需要知道「哪些 IP 已被 eBPF 直接放行」，否則它會替這些地址換上假 IP，
// 讓 kernel 端的 bypass 判定永遠落空。
var bypassIPSet atomic.Pointer[netipx.IPSet]

// BypassIPSet returns the effective bypass IP set, or nil when bypass_rule_set is not in use.
func BypassIPSet() *netipx.IPSet {
	return bypassIPSet.Load()
}

// SetBypassIPSet publishes or clears the bypass IP set seen by BypassIPSet; nil clears it.
func SetBypassIPSet(ipSet *netipx.IPSet) {
	bypassIPSet.Store(ipSet)
}

type bypassRuleSetSubscription struct {
	ruleSet adapter.RuleSet
	element *list.Element[adapter.RuleSetUpdateCallback]
}

// bypassRuleSetSubscriptions implements io.Closer so Inbound.bypassRuleSetCallback
// keeps its declared type while holding one callback handle per rule-set.
type bypassRuleSetSubscriptions struct {
	subscriptions []bypassRuleSetSubscription
}

func (s *bypassRuleSetSubscriptions) Close() error {
	for _, subscription := range s.subscriptions {
		subscription.ruleSet.UnregisterCallback(subscription.element)
		subscription.ruleSet.DecRef()
	}
	s.subscriptions = nil
	return nil
}

// setupBypassRuleSets resolves the bypass_rule_set tags once, at inbound creation.
func (i *Inbound) setupBypassRuleSets(router adapter.Router) error {
	if len(i.options.BypassRuleSet) == 0 {
		return nil
	}
	if router == nil {
		return E.New("bypass_rule_set requires a router that exposes rule-sets")
	}
	if i.bypassRuleSet != nil {
		return E.New("bypass_rule_set already resolved")
	}
	for _, ruleSetTag := range i.options.BypassRuleSet {
		ruleSet, loaded := router.RuleSet(ruleSetTag)
		if !loaded {
			return E.New("parse bypass_rule_set: rule-set not found: ", ruleSetTag)
		}
		i.bypassRuleSet = append(i.bypassRuleSet, ruleSet)
	}
	return nil
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	subscriptions := &bypassRuleSetSubscriptions{}
	for _, ruleSet := range i.bypassRuleSet {
		// IncRef：rule-set 在 refs==0 時會被 Cleanup() 清空解析結果，bypass 清單會無聲地變空。
		ruleSet.IncRef()
		subscriptions.subscriptions = append(subscriptions.subscriptions, bypassRuleSetSubscription{
			ruleSet: ruleSet,
			element: ruleSet.RegisterCallback(i.updateBypassRuleSet),
		})
	}
	i.bypassRuleSetCallback = subscriptions
	i.bypassRuleSetStarted = true
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	if i.bypassRuleSetCallback != nil {
		_ = i.bypassRuleSetCallback.Close()
		i.bypassRuleSetCallback = nil
	}
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(ruleSet adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		if backend := i.backendInstance(); backend != nil && !backend.IsClosed() {
			logErrorf("[EBPF] refresh bypass_rule_set: %s", err.Error())
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) currentBypassCIDR() []netip.Prefix {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	return slices.Clone(i.bypassCIDR)
}

func (i *Inbound) refreshHostAddresses(backend *ECommon.CgroupBackend) error {
	prefixes := localInterfacePrefixes()
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr())
	}
	if err := backend.UpdateHostAddresses(addresses); err != nil {
		return E.Cause(err, "update eBPF local interface host addresses")
	}
	return nil
}

func (i *Inbound) refreshBypassCIDRsLocked() (bool, error) {
	var prefixes []netip.Prefix
	for _, ruleSet := range i.bypassRuleSet {
		for _, ipSet := range ruleSet.ExtractIPSet() {
			if ipSet == nil {
				continue
			}
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	backend := i.backendInstance()
	if backend == nil {
		return false, E.New("eBPF backend is not initialized")
	}
	if err := i.refreshHostAddresses(backend); err != nil {
		return false, err
	}
	updated, err := backend.UpdateBypassCIDR(prefixes)
	if err != nil {
		return false, err
	}
	i.bypassCIDR = prefixes
	// Keep the shared-network backend's bypass flags in sync. It reuses the
	// cgroup backend's bypass maps, so only the control presence flags need to
	// follow the effective CIDR set (including runtime bypass_rule_set changes).
	if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil && !sharedBackend.IsClosed() {
			ipv4Count, ipv6Count := backend.BypassCIDRCount()
			if stateErr := sharedBackend.SetBypassCIDRState(ipv4Count, ipv6Count); stateErr != nil {
				logErrorf("[EBPF] refresh shared-network bypass CIDR state: %s", stateErr.Error())
			}
		}
	}
	// Publish the effective bypass CIDR set to the DNS fake-ip middleware so
	// domains whose real addresses fall inside it keep their real IP and the
	// kernel eBPF bypass can engage. Only publish when bypass_rule_set is used.
	if len(i.bypassRuleSet) > 0 {
		var builder netipx.IPSetBuilder
		for _, prefix := range prefixes {
			builder.AddPrefix(prefix)
		}
		bypassSet, buildErr := builder.IPSet()
		if buildErr == nil {
			bypassIPSet.Store(bypassSet)
		}
	} else {
		bypassIPSet.Store(nil)
	}
	return updated, nil
}
