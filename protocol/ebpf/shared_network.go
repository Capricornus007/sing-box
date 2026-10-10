//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
	LC "github.com/sagernet/sing-box/option"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/udpnat2"

	tun "github.com/sagernet/sing-tun"
)

type sharedNetwork struct {
	inbound        *Inbound
	interfaces     []string
	options        LC.EBPFShared
	sharedBackend  *ECommon.SharedNetworkBackend
	tcManager      *sharedTCManager
	listeners      internalListenerSet
	udpNat         *udpnat.Service
	udpClientTable udpClientTable
	udpWarnings    udpWarningLimiters
	mapCapacity    ECommon.SharedNetworkMapCapacities
	tcPriority     uint16

	lifecycleAccess sync.RWMutex
	backendAccess   sync.RWMutex
	periodicStop    chan struct{}
	periodicDone    chan struct{}
}

func newSharedNetwork(inbound *Inbound, sharedOptions LC.EBPFShared, mapCapacity ECommon.SharedNetworkMapCapacities) *sharedNetwork {
	tcPriority := sharedOptions.Advanced.TCPriority
	if tcPriority == 0 {
		tcPriority = defaultSharedNetworkTCPriority
	}
	shared := &sharedNetwork{
		inbound:     inbound,
		interfaces:  append([]string(nil), sharedOptions.Interface...),
		options:     sharedOptions,
		mapCapacity: mapCapacity,
		tcPriority:  tcPriority,
	}
	// 與本機模式各持一個 udpnat2 service：兩邊的 client 位址空間可能重疊
	// （例如本機程式與下游台站用同一個 port），共用一張表會把封包塞進
	// 錯的轉發狀態。timeout 由 normalizeUDPTimeout 保證非零，否則 udpnat.New 會 panic。
	shared.udpNat = udpnat.New(shared, shared.preparePacketConnection, inbound.udpTimeout, false)
	return shared
}

func (s *sharedNetwork) Start(cgroupBackend *ECommon.CgroupBackend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort:         s.listeners.selectedPort(),
		EnableTCP:            s.inbound.enableTCP,
		EnableUDP:            s.inbound.enableUDP,
		HijackDNS:            s.inbound.dnsMode != dnsModeOff,
		DNSRespectBypass:     s.inbound.dnsMode == dnsModeRespectBypass,
		BypassPrivateAddress: s.inbound.bypassPrivateAddress,
		RedirectIPv4:         s.inbound.redirectIPv4Prefix,
		RedirectIPv6:         s.inbound.sharedRedirectIPv6Prefix(),
		IncludeSourceCIDR:    s.options.IncludeSourceCIDR,
		ExcludeSourceCIDR:    s.options.ExcludeSourceCIDR,
		IncludeSourceMAC:     s.inbound.sharedNetworkIncludeMAC,
		ExcludeSourceMAC:     s.inbound.sharedNetworkExcludeMAC,
		MapCapacity:          s.mapCapacity,
		UDPTimeout:           s.inbound.udpTimeout,
	})
	if err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.setSharedBackend(backend)
	if cgroupBackend == nil {
		if _, err = backend.UpdateBypassCIDR(s.inbound.currentBypassCIDR()); err != nil {
			return E.Errors(err, s.Close())
		}
	} else {
		ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
		if err = backend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
			return E.Errors(err, s.Close())
		}
	}
	s.tcManager = &sharedTCManager{
		backend:     backend,
		interfaces:  s.interfaces,
		enableIPv4:  s.inbound.redirectIPv4Prefix.IsValid(),
		priority:    s.tcPriority,
		attachments: make(map[string]*sharedTCAttachment),
	}
	if monitor, monitorErr := tun.NewNetworkUpdateMonitor(log.StdLogger()); monitorErr == nil {
		s.tcManager.networkMonitor = monitor
	}
	if err = s.tcManager.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	s.startUDPPeriodic()
	logInfof("[EBPF] shared-network TC interception ready: downstream_interfaces=[%s], redirect_listener_port=%d, dns_mode=%s, ipv6_mode=%s, bypass_private_address=%v, source_cidr={include:%d, exclude:%d}, tc_priority=%d, map_capacity=%d, programs=[tc/ingress, tc/egress]",
		s.tcManager.InterfaceString(),
		s.listeners.selectedPort(),
		s.inbound.dnsMode,
		s.inbound.sharedIPv6Mode,
		s.inbound.bypassPrivateAddress,
		len(s.options.IncludeSourceCIDR),
		len(s.options.ExcludeSourceCIDR),
		s.tcPriority,
		s.mapCapacity,
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	return s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.redirectIPv6Prefix.IsValid(),
		s.newListener,
	)
}

func (s *sharedNetwork) newListener(network string, ipv6 bool, port uint16) (*internalListener, error) {
	return newInternalListener(s.inbound.socketControl(ipv6), network, ipv6, port, s)
}

func (s *sharedNetwork) startUDPPeriodic() {
	s.periodicStop = make(chan struct{})
	s.periodicDone = make(chan struct{})
	go s.udpPeriodicLoop(s.periodicStop, s.periodicDone)
}

func (s *sharedNetwork) stopUDPPeriodic() {
	if s.periodicStop == nil {
		return
	}
	close(s.periodicStop)
	<-s.periodicDone
	s.periodicStop = nil
}

func (s *sharedNetwork) udpPeriodicLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	interval := s.inbound.udpTimeout / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			// freelru 取到既有 session 時只會續期、不檢查過期，逾期掃由這邊驅動，
			// 否則逾期的 client 會被重複使用、session 永遠不關。
			s.udpNat.PurgeExpired()
			s.udpClientTable.sweep(time.Now(), s.inbound.udpTimeout, s.releaseFlows)
			if backend := s.sharedBackendInstance(); backend != nil && !backend.IsClosed() {
				idle := 2 * s.inbound.udpTimeout
				if idle < 30*time.Second {
					idle = 30 * time.Second
				}
				if result, sweepErr := backend.SweepOrphanedFlows(idle, 1024); sweepErr != nil {
					s.udpWarnings.cleanup.warn(s.inbound.logWarn, "sweep orphaned shared-network flows: ", sweepErr)
				} else if result.Removed > 0 {
					logDebugf("[EBPF] swept %d orphaned shared-network flows", result.Removed)
				}
			}
		}
	}
}

func (s *sharedNetwork) InterfaceUpdated() {
	// 介面換了，TC flow 與既有的 per-client session 都失去意義，兩邊一起清掉，
	// 下一個封包才會照新介面重建 flow 並開出一條新 session。
	s.udpNat.Purge()
	s.udpClientTable.sweep(time.Now(), 0, s.releaseFlows)
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	if manager := s.tcManager; manager != nil {
		manager.Wake()
	}
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	s.stopUDPPeriodic()
	// 先關掉 per-client session，讓上層的讀迴圈在 backend 與監聽孔拆除前就收尾。
	s.udpNat.Purge()
	var closeErr error
	if s.tcManager != nil {
		tcErr := s.tcManager.Close()
		closeErr = E.Errors(closeErr, tcErr)
		if tcErr == nil {
			s.tcManager = nil
		}
	}
	var backendErr error
	if backend := s.sharedBackendInstance(); backend != nil {
		backendErr = backend.Close()
		if backend.IsClosed() {
			s.setSharedBackend(nil)
		}
	}
	return E.Errors(closeErr, backendErr, s.closeListeners())
}

func (s *sharedNetwork) closeListeners() error {
	return s.listeners.close()
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	return s.tcManager == nil && s.sharedBackendInstance() == nil && s.listeners.isClosed()
}

func (s *sharedNetwork) sharedBackendInstance() *ECommon.SharedNetworkBackend {
	s.backendAccess.RLock()
	defer s.backendAccess.RUnlock()
	return s.sharedBackend
}

func (s *sharedNetwork) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
}

func (s *sharedNetwork) acceptWarn(message ...any) {
	s.udpWarnings.accept.warn(s.inbound.logWarn, message...)
}

func (s *sharedNetwork) packetWarn(message ...any) {
	s.udpWarnings.packetInfo.warn(s.inbound.logWarn, message...)
}

var _ internalListenerHandler = (*sharedNetwork)(nil)
