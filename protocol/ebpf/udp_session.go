//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// udpSessionOwner 是 per-client UDP session 對所屬轉發模式的依賴：
// 一張 forwarding 狀態表加一個回包寫法。本機 cgroup 與 shared-network
// 各實作一份，session 那套生命週期規則因此只有一份程式碼、兩種模式行為一致。
type udpSessionOwner interface {
	udpTable() *udpClientTable
	writeUDPPacket(clientState *udpClientState, client netip.AddrPort, destination netip.AddrPort, data []byte) error
}

// udpSessionWriter 是交給 udpnat2 的回包寫入器：一條 session 一個實例，
// 上層（outbound/relay）寫回時用的是它從 ReadPacket 拿到的 destination，
// 也就是 App 原本要連的位址，正好是 redirectBinding 的索引鍵。
//
// clientState 一律在寫入當下向 udpClientTable 查，不使用 session 建立時抓到的指標：
// udpClientTable 的 TTL 清掃可能比 udpnat2 的 session 更快回收這個 client，
// 屆時新封包會重建 clientState，舊指標裡已經是被清空的 bindings，
// 一直用舊指標會讓這條 session 之後的回包全數失敗。
type udpSessionWriter struct {
	owner    udpSessionOwner
	client   netip.AddrPort
	captured *udpClientState
}

func (w *udpSessionWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	clientState, loaded := w.owner.udpTable().load(w.client)
	if !loaded {
		clientState = w.captured
	}
	if clientState == nil {
		return E.New("missing UDP session state for ", w.client)
	}
	// buffer 不屬於我們：N.PacketConn.WritePacket 的呼叫端保留擁有權，
	// udpnat2 的 natConn 也只是轉發。在這裡釋放會讓上層重複釋放同一個 buffer。
	return w.owner.writeUDPPacket(clientState, w.client, destination.AddrPort(), buffer.Bytes())
}

// prepareUDPSession 實作 udpnat2 的 PrepareFunc。只有在 udpClientTable 查不到
// 狀態時才退回 loadOrCreate：正常路徑下 NewPacket 已經算好這個 client 的
// clientState 並用 userData 帶進來，這裡不該再碰封包的 original destination。
func prepareUDPSession(
	owner udpSessionOwner,
	parent context.Context,
	source M.Socksaddr,
	userData any,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	clientState, _ := userData.(*udpClientState)
	if clientState == nil {
		clientState = owner.udpTable().loadOrCreate(source.AddrPort())
	}
	return true,
		log.ContextWithNewID(parent),
		&udpSessionWriter{owner: owner, client: source.AddrPort(), captured: clientState},
		nil
}

// udpSessionMetadata 組出整條 session 共用的 InboundContext。
// destination 是 udpnat2 建 session 時那一包的原始目的位址（不是 eBPF 的
// token 位址），後面的封包即使目的地不同，也照 upstream 對 source key 的
// 既定行為沿用這條 session 的路由判定。
func (i *Inbound) udpSessionMetadata(source M.Socksaddr, destination M.Socksaddr) adapter.InboundContext {
	return adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkUDP,
		Source:      source,
		Destination: destination,
	}
}
