//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/dns"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

// safeDNSPacketSize 保留 mihomo 的 2048 硬上限，因為我方的 TruncateDNSMessage 只照客戶端宣告的 EDNS 大小封頂。
const safeDNSPacketSize = 2 * 1024

// 不用 constant.DNSTimeout（10 秒）：DNS 攔截是應用在前台等解析，等滿 10 秒會直接表現為卡死。
const dnsRelayTimeout = 5 * time.Second

// hijackDNS：dns-mode 非 off 時，核心已經把 53 埠重導向進內部監聽孔，這些封包只能交給我方 DNSRouter 應答，再當一般連線路由出去會查詢到自己發的請求。
func (i *Inbound) hijackDNS(destination netip.AddrPort) bool {
	return i.dnsMode != dnsModeOff && destination.Port() == 53
}

func (i *Inbound) relayTCPDNS(router adapter.DNSRouter, metadata adapter.InboundContext, conn net.Conn) {
	if err := serveDNSStream(i.ctx, router, metadata, conn); err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "relay hijacked TCP DNS: ", err)
	}
}

func (s *sharedNetwork) relayTCPDNS(router adapter.DNSRouter, metadata adapter.InboundContext, conn net.Conn, flow *ECommon.SharedNetworkFlowHandle) {
	defer s.releaseFlow(flow)
	if err := serveDNSStream(s.inbound.ctx, router, metadata, conn); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "relay hijacked TCP DNS: ", err)
	}
}

func (i *Inbound) relayUDPDNS(router adapter.DNSRouter, metadata adapter.InboundContext, data []byte, client netip.AddrPort, clientState *udpClientState, destination netip.AddrPort) {
	serveDNSPacket(i.ctx, router, metadata, &i.listeners, &i.udpWarnings, i.logWarn, client, clientState, destination, data)
}

func (s *sharedNetwork) relayUDPDNS(router adapter.DNSRouter, metadata adapter.InboundContext, data []byte, client netip.AddrPort, clientState *udpClientState, destination netip.AddrPort) {
	serveDNSPacket(s.inbound.ctx, router, metadata, &s.listeners, &s.udpWarnings, s.inbound.logWarn, client, clientState, destination, data)
}

// serveDNSStream 自己包迴圈是因為我方 HandleStreamDNSRequest 只處理單筆查詢，mihomo 版是在 RelayDnsConn 內部自己迴圈。
func serveDNSStream(ctx context.Context, router adapter.DNSRouter, metadata adapter.InboundContext, conn net.Conn) error {
	defer conn.Close()
	// Destination 留著會讓 DNS 規則拿 eBPF 發的 token 位址去比對。
	metadata.Destination = M.Socksaddr{}
	for {
		conn.SetReadDeadline(time.Now().Add(dnsRelayTimeout))
		err := dnsOutbound.HandleStreamDNSRequest(ctx, router, conn, metadata)
		if err != nil {
			if E.IsClosedOrCanceled(err) {
				return nil
			}
			return err
		}
	}
}

// serveDNSPacket 自己實作是因為 mihomo 的 RelayDnsPacket 打的是全域 resolver service，我方改成由上層注入 DNSRouter。
func serveDNSPacket(
	ctx context.Context,
	router adapter.DNSRouter,
	metadata adapter.InboundContext,
	listeners *internalListenerSet,
	limiters *udpWarningLimiters,
	warn warningLogger,
	client netip.AddrPort,
	clientState *udpClientState,
	destination netip.AddrPort,
	query []byte,
) {
	binding, loaded := clientState.redirectBinding(destination)
	if !loaded {
		limiters.originalDestination.warn(warn, "missing UDP DNS binding for ", client)
		return
	}
	if listeners.udpConn(binding.address.Is6()) == nil {
		limiters.originalDestination.warn(warn, "eBPF UDP DNS listener is unavailable")
		return
	}
	var message mDNS.Msg
	if err := message.Unpack(query); err != nil {
		limiters.originalDestination.warn(warn, "unpack hijacked UDP DNS: ", err)
		return
	}
	if !metadata.Source.IsValid() {
		metadata.Source = M.SocksaddrFromNetIP(client)
	}
	// 同 TCP，token 位址當 Destination 會讓 DNS 規則比對到錯的對象。
	metadata.Destination = M.Socksaddr{}
	writer := &dnsRedirectWriter{listeners: listeners, packetInfo: binding.packetInfo, address: binding.address}
	// 用 ExchangeAsync 是因為封包是從單一讀取迴圈餵進來的，同步等待會讓一條慢查詢卡死整個 UDP 通道。
	router.ExchangeAsync(
		adapter.WithContext(ctx, &metadata),
		&message,
		adapter.DNSQueryOptions{Timeout: dnsRelayTimeout},
		func(response *mDNS.Msg, exchangeErr error) {
			if exchangeErr != nil {
				limiters.originalDestination.warn(warn, "relay hijacked UDP DNS: ", exchangeErr)
				response = &mDNS.Msg{}
				response.SetRcode(&message, mDNS.RcodeServerFailure)
			}
			if writeErr := writeDNSReply(writer, &message, response, M.SocksaddrFromNetIP(client)); writeErr != nil {
				limiters.cleanup.warn(warn, "write hijacked UDP DNS reply: ", writeErr)
			}
		},
	)
}

// writeDNSReply 先壓到 safeDNSPacketSize 再給 tree 的截斷函式，是因為後者不看這個硬上限。
func writeDNSReply(writer N.PacketWriter, message *mDNS.Msg, response *mDNS.Msg, destination M.Socksaddr) error {
	// 一律 Copy() 再改：response 可能是 DNS router 跨連線共用的指標，
	// 就地開 Compress 或 Truncate 會 data race、也會污染別的查詢結果。
	response = response.Copy()
	response.Compress = true
	if response.Len() > safeDNSPacketSize {
		response.Truncate(safeDNSPacketSize)
	}
	responseBuffer, err := dns.TruncateDNSMessage(message, response, N.CalculateFrontHeadroom(writer), N.CalculateRearHeadroom(writer))
	if err != nil {
		return err
	}
	return writer.WritePacket(responseBuffer, destination)
}

// dnsRedirectWriter 存在是因為我方沒有能自帶 IP_PKTINFO 來源位址的 N.PacketConn，回包一定要從 eBPF 的重導向監聽孔寫回。
type dnsRedirectWriter struct {
	listeners  *internalListenerSet
	packetInfo []byte
	address    netip.Addr
}

func (w *dnsRedirectWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	return w.listeners.writeUDP(buffer.Bytes(), w.packetInfo, destination.AddrPort(), w.address)
}

var _ N.PacketWriter = (*dnsRedirectWriter)(nil)
