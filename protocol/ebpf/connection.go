//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"

	N "github.com/sagernet/sing/common/network"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

var (
	_ N.UDPConnectionHandlerEx = (*Inbound)(nil)
	_ udpSessionOwner          = (*Inbound)(nil)
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
	metadata := i.udpSessionMetadata(
		M.SocksaddrFromNetIP(client),
		M.SocksaddrFromNetIP(original.Destination),
	)
	if i.hijackDNS(original.Destination) {
		i.relayUDPDNS(i.dnsRouter, metadata, data, client, clientState, original.Destination)
		return
	}

	// session 以 client 的 source addr:port 為鍵（跟上游 tproxy/direct 一致），
	// 同一個 client 的後續 datagram 會排進同一條 RoutePacketConnection，
	// 不再每包一條連線。真正的原目的地放在每一包的 destination 參數裡，
	// 由 natConn 的 ReadPacket 原樣回報給上層。
	i.udpNat.NewPacket(
		[][]byte{data},
		M.SocksaddrFromNetIP(client),
		M.SocksaddrFromNetIP(original.Destination),
		clientState,
	)
}

// preparePacketConnection 是 udpnat2 建立 session 時的回呼，本機模式把
// 自己的 context 與 udpClientTable 交給共用的 prepareUDPSession。
func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return prepareUDPSession(i, i.ctx, source, userData)
}

// NewPacketConnectionEx 由 udpnat2 在 session 建立時另起 goroutine 呼叫，
// 一條 session 只進這裡一次；RoutePacketConnection 會擋到 session 結束，
// 所以結束時要關掉它，讓 udpnat2 的快取能把這條 natConn 淘汰。
func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	i.routePacketConnection(ctx, conn, i.udpSessionMetadata(source, destination))
}

func (i *Inbound) routePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) {
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	if err := i.router.RoutePacketConnection(ctx, conn, metadata); err != nil {
		i.logWarn("route UDP packet connection: ", err)
	}
	_ = conn.Close()
}

func (i *Inbound) udpTable() *udpClientTable {
	return &i.udpClientTable
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
