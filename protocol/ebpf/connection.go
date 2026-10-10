//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"

	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

func (i *Inbound) NewConnection(conn net.Conn) {
	backend := i.backendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	localAddr, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	original, err := backend.TakeOriginal(ECommon.ProtocolTCP, localAddr)
	if err != nil {
		i.logWarn("lookup TCP original destination: ", err)
		_ = conn.Close()
		return
	}
	sourceAddr, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkTCP,
		Source:      M.SocksaddrFromNetIP(sourceAddr),
		Destination: M.SocksaddrFromNetIP(original.Destination),
	}
	if i.hijackDNS(original.Destination) {
		go i.relayTCPDNS(i.dnsRouter, metadata, conn)
		return
	}
	i.routeConnection(conn, metadata)
}

func (i *Inbound) routeConnection(conn net.Conn, metadata adapter.InboundContext) {
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	if err := i.router.RouteConnection(i.ctx, conn, metadata); err != nil {
		i.logWarn("route TCP connection: ", err)
	}
	_ = conn.Close()
}

func (i *Inbound) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logWarn, "read UDP redirect address: ", err)
		return
	}
	client := source
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
	cached, bindingReady, loaded := i.udpClientTable.cachedPacketState(client, redirectAddress)
	original := cached.original
	if !loaded {
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverUDPOriginal(redirectDestination)
			if err == nil {
				i.udpWarnings.originalDestination.warn(i.logWarn, "recovered UDP original destination")
			}
		}
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverConnectedUDPOriginal(redirectDestination)
			if err == nil {
				i.udpWarnings.originalDestination.warn(i.logWarn, "recovered connected UDP original destination")
			}
		}
		if err != nil {
			i.udpWarnings.originalDestination.warn(i.logWarn, "lookup UDP original destination: ", err)
			return
		}
	}
	if !bindingReady {
		releasedRedirects := i.udpClientTable.setBinding(
			client,
			original.Destination,
			redirectAddress,
			original.ConnectedUDP,
		)
		i.deleteUDPRedirects(releasedRedirects)
	}

	clientState := i.udpClientTable.loadOrCreate(client)
	if original.ConnectedUDP {
		clientState.setConnected(true)
	}
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkUDP,
		Source:      M.SocksaddrFromNetIP(client),
		Destination: M.SocksaddrFromNetIP(original.Destination),
	}
	if i.hijackDNS(original.Destination) {
		i.relayUDPDNS(i.dnsRouter, metadata, data, client, clientState, original.Destination)
		return
	}

	i.routePacketConnection(
		&udpPacketConn{
			inbound:     i,
			client:      client,
			clientState: clientState,
			destination: M.SocksaddrFromNetIP(original.Destination),
			data:        data,
		},
		metadata,
	)
}

func (i *Inbound) routePacketConnection(conn N.PacketConn, metadata adapter.InboundContext) {
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	if err := i.router.RoutePacketConnection(i.ctx, conn, metadata); err != nil {
		i.logWarn("route UDP packet connection: ", err)
	}
	_ = conn.Close()
}

// udpPacketConn 把 eBPF 抓到的單一 datagram 包成 sing-box 的 PacketConn。
// 目前每個 datagram 一進一出即結束，因此上層看到的 UDP session 生命週期
// 只有單一封包，要改成 per-client 復用得接 udpnat。
type udpPacketConn struct {
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
	destination M.Socksaddr
	data        []byte
	closed      bool
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.closed {
		return M.Socksaddr{}, io.EOF
	}
	if c.data == nil {
		return M.Socksaddr{}, io.EOF
	}
	buffer.Write(c.data)
	c.data = nil
	return c.destination, nil
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.inbound.writeUDPPacket(c.clientState, c.client, destination.AddrPort(), buffer.Bytes())
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.client)
}

func (c *udpPacketConn) Close() error {
	c.closed = true
	return nil
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// destination 是 redirectBinding 的鍵：bindings 以「App 原本要連的位址」索引，
// 不是 client 位址，拿 client 去查會一律 miss 而讓 UDP 回包全丟。
func (i *Inbound) writeUDPPacket(clientState *udpClientState, client netip.AddrPort, destination netip.AddrPort, data []byte) error {
	if clientState == nil {
		return E.New("missing UDP redirect state for ", client)
	}
	binding, loaded := clientState.redirectBinding(destination)
	if !loaded {
		return E.New("missing UDP redirect binding for ", destination)
	}
	udpConn := i.listeners.udpConn(binding.address.Is6())
	if udpConn == nil {
		return E.New("eBPF UDP listener is unavailable")
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(data, binding.packetInfo, client)
	return err
}

func (i *Inbound) deleteUDPRedirects(redirectAddresses []netip.Addr) {
	if len(redirectAddresses) == 0 {
		return
	}
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	for _, redirectAddress := range redirectAddresses {
		redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
		if err := backend.DeleteRedirect(ECommon.ProtocolUDP, redirectDestination); err != nil {
			i.udpWarnings.cleanup.warn(i.logWarn, "delete UDP redirect mapping for ", redirectDestination, ": ", err)
		}
	}
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	for len(oob) > 0 {
		header, data, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return netip.Addr{}, E.Cause(err, "parse IP packet info")
		}
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO:
			if len(data) < unix.SizeofInet4Pktinfo {
				return netip.Addr{}, E.New("invalid IPv4 packet info length: ", len(data))
			}
			var address [4]byte
			copy(address[:], data[8:12])
			return netip.AddrFrom4(address), nil
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO:
			if len(data) < unix.SizeofInet6Pktinfo {
				return netip.Addr{}, E.New("invalid IPv6 packet info length: ", len(data))
			}
			var address [16]byte
			copy(address[:], data[:16])
			return netip.AddrFrom16(address), nil
		}
		oob = remainder
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}
