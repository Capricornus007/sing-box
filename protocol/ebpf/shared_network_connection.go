//go:build with_ebpf && (linux || android)

package ebpf

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
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
	metadata := adapter.InboundContext{
		Inbound:     s.inbound.Tag(),
		InboundType: s.inbound.Type(),
		Network:     N.NetworkUDP,
		Source:      M.SocksaddrFromNetIP(client),
		Destination: M.SocksaddrFromNetIP(original.Destination),
	}
	if s.inbound.hijackDNS(original.Destination) {
		s.relayUDPDNS(s.inbound.dnsRouter, metadata, data, client, clientState, original.Destination)
		return
	}

	s.inbound.routePacketConnection(
		&sharedPacketConn{
			shared:      s,
			client:      client,
			clientState: clientState,
			destination: M.SocksaddrFromNetIP(original.Destination),
			data:        data,
		},
		metadata,
	)
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

// sharedPacketConn 與本機模式的 udpPacketConn 同形：一個 datagram 一個連線，
// 差别只在回包要經 shared-network 的 flow 與它自己的 UDP socket。
type sharedPacketConn struct {
	shared      *sharedNetwork
	client      netip.AddrPort
	clientState *udpClientState
	destination M.Socksaddr
	data        []byte
	closed      bool
}

func (c *sharedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.closed || c.data == nil {
		return M.Socksaddr{}, io.EOF
	}
	buffer.Write(c.data)
	c.data = nil
	return c.destination, nil
}

func (c *sharedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.shared.writeUDPPacket(c.clientState, c.client, destination.AddrPort(), buffer.Bytes())
}

func (c *sharedPacketConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.client)
}

func (c *sharedPacketConn) Close() error {
	c.closed = true
	return nil
}

func (c *sharedPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *sharedPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *sharedPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
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
