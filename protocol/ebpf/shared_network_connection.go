//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ N.UDPConnectionHandlerEx = (*sharedNetwork)(nil)
	_ udpSessionOwner          = (*sharedNetwork)(nil)
)

func (s *sharedNetwork) NewConnection(conn net.Conn) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	client, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	tokenDestination, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	original, flow, err := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
	if err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "lookup shared-network TCP original destination: ", err)
		_ = conn.Close()
		return
	}
	metadata := adapter.InboundContext{
		Inbound:     s.inbound.Tag(),
		InboundType: s.inbound.Type(),
		Network:     N.NetworkTCP,
		Source:      M.SocksaddrFromNetIP(client),
		Destination: M.SocksaddrFromNetIP(original.Destination),
	}
	if s.inbound.hijackDNS(original.Destination) {
		go s.relayTCPDNS(s.inbound.dnsRouter, metadata, conn, flow)
		return
	}
	s.inbound.routeConnection(&sharedConn{Conn: conn, shared: s, flow: flow}, metadata)
}

func (s *sharedNetwork) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	tokenAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		s.udpWarnings.packetInfo.warn(s.inbound.logWarn, "read shared-network UDP token address: ", err)
		return
	}
	client := source
	tokenDestination := netip.AddrPortFrom(tokenAddress, s.listeners.selectedPort())
	cached, bindingReady, loaded := s.udpClientTable.cachedPacketState(client, tokenAddress)
	original := cached.original
	flow := cached.sharedFlow
	if !loaded {
		original, flow, err = backend.LookupFlow(ECommon.ProtocolUDP, client, tokenDestination)
		if err != nil {
			s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "lookup shared-network UDP original destination: ", err)
			return
		}
	}
	if !bindingReady {
		released := s.udpClientTable.setSharedBinding(client, original.Destination, tokenAddress, flow)
		s.releaseFlows(released)
	}

	clientState := s.udpClientTable.loadOrCreate(client)
	metadata := s.inbound.udpSessionMetadata(
		M.SocksaddrFromNetIP(client),
		M.SocksaddrFromNetIP(original.Destination),
	)
	if s.inbound.hijackDNS(original.Destination) {
		s.relayUDPDNS(s.inbound.dnsRouter, metadata, data, client, clientState, original.Destination)
		return
	}

	// 與本機模式同一套 session 規則：以 client 的 source addr:port 為鍵，
	// 同一個 client 的多個 datagram 共用一條 RoutePacketConnection。
	s.udpNat.NewPacket(
		[][]byte{data},
		M.SocksaddrFromNetIP(client),
		M.SocksaddrFromNetIP(original.Destination),
		clientState,
	)
}

// preparePacketConnection 是 udpnat2 建立 session 時的回呼，shared-network
// 模式只換回包寫法（走 TC flow 對應的 UDP socket），session 生命週期一樣。
func (s *sharedNetwork) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return prepareUDPSession(s, s.inbound.ctx, source, userData)
}

// NewPacketConnectionEx 由 udpnat2 在 session 建立時另起 goroutine 呼叫，
// 一條 session 只進這裡一次，路由判定沿用建 session 那一包的原目的地。
func (s *sharedNetwork) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.inbound.routePacketConnection(ctx, conn, s.inbound.udpSessionMetadata(source, destination))
}

func (s *sharedNetwork) udpTable() *udpClientTable {
	return &s.udpClientTable
}

func (s *sharedNetwork) releaseFlows(releases []udpRedirectRelease) {
	for _, release := range releases {
		s.releaseFlow(release.sharedFlow)
	}
}

func (s *sharedNetwork) releaseFlow(flow *ECommon.SharedNetworkFlowHandle) {
	if flow == nil {
		return
	}
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	if err := backend.ReleaseFlow(flow); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "release shared-network flow: ", err)
	}
}

type sharedConn struct {
	net.Conn
	shared *sharedNetwork
	flow   *ECommon.SharedNetworkFlowHandle
	once   sync.Once
}

func (c *sharedConn) Close() error {
	c.once.Do(func() {
		c.shared.releaseFlow(c.flow)
	})
	return c.Conn.Close()
}

func (s *sharedNetwork) writeUDPPacket(clientState *udpClientState, client netip.AddrPort, destination netip.AddrPort, data []byte) error {
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	if clientState == nil {
		return E.New("missing shared-network UDP state for ", client)
	}
	binding, loaded := clientState.redirectBinding(destination)
	if !loaded {
		return E.New("missing shared-network UDP binding for ", destination)
	}
	return s.listeners.writeUDP(data, binding.packetInfo, client, binding.address)
}
