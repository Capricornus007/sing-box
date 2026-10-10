//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"
)

type recordedUDPReply struct {
	state       *udpClientState
	client      netip.AddrPort
	destination netip.AddrPort
	data        string
}

// fakeUDPSessionOwner 只取代「把回包從 token 位址寫回 client」這一段，
// 綁定查照的鍵語意跟真的 Inbound.writeUDPPacket 一模一樣。
type fakeUDPSessionOwner struct {
	table   udpClientTable
	access  sync.Mutex
	replies []recordedUDPReply
}

func (f *fakeUDPSessionOwner) udpTable() *udpClientTable {
	return &f.table
}

func (f *fakeUDPSessionOwner) writeUDPPacket(clientState *udpClientState, client netip.AddrPort, destination netip.AddrPort, data []byte) error {
	if clientState == nil {
		return E.New("missing UDP redirect state for ", client)
	}
	if _, loaded := clientState.redirectBinding(destination); !loaded {
		return E.New("missing UDP redirect binding for ", destination)
	}
	f.access.Lock()
	defer f.access.Unlock()
	f.replies = append(f.replies, recordedUDPReply{
		state:       clientState,
		client:      client,
		destination: destination,
		data:        string(data),
	})
	return nil
}

func (f *fakeUDPSessionOwner) recorded() []recordedUDPReply {
	f.access.Lock()
	defer f.access.Unlock()
	return append([]recordedUDPReply(nil), f.replies...)
}

func TestUDPSessionWriterLooksUpBindingByDestination(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:53111")
	redirectAddress := netip.MustParseAddr("127.128.0.10")
	destination := netip.MustParseAddrPort("198.51.100.7:443")
	owner := &fakeUDPSessionOwner{}
	owner.table.setBinding(client, destination, redirectAddress, false)
	clientState, loaded := owner.table.load(client)
	if !loaded {
		t.Fatal("expected UDP client state")
	}

	ok, _, writer, _ := prepareUDPSession(owner, context.Background(), M.SocksaddrFromNetIP(client), clientState)
	if !ok {
		t.Fatal("prepare did not accept the session")
	}
	buffer := buf.NewPacket()
	buffer.WriteString("reply")
	if err := writer.WritePacket(buffer, M.SocksaddrFromNetIP(destination)); err != nil {
		t.Fatalf("write session reply: %s", err)
	}
	buffer.Release()

	replies := owner.recorded()
	if len(replies) != 1 {
		t.Fatalf("expected one recorded reply, got %d", len(replies))
	}
	if replies[0].destination != destination {
		t.Fatalf("reply must be keyed by the original destination, got %s", replies[0].destination)
	}
	if replies[0].client != client {
		t.Fatalf("unexpected reply client: %s", replies[0].client)
	}
	if replies[0].data != "reply" {
		t.Fatalf("unexpected reply payload: %q", replies[0].data)
	}

	// 沒見過的目的地一定要報錯：拿 client 當鍵會一律 miss 而讓回包靜默全丟。
	unboundDestination := M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.9:53"))
	unknown := buf.NewPacket()
	unknown.WriteString("lost")
	if err := writer.WritePacket(unknown, unboundDestination); err == nil {
		t.Fatal("expected an error for an unbound destination")
	}
	unknown.Release()
}

func TestUDPSessionWriterFollowsRecreatedClientState(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:53111")
	redirectAddress := netip.MustParseAddr("127.128.0.10")
	destination := netip.MustParseAddrPort("198.51.100.7:443")
	owner := &fakeUDPSessionOwner{}
	owner.table.setBinding(client, destination, redirectAddress, false)
	staleState, loaded := owner.table.load(client)
	if !loaded {
		t.Fatal("expected UDP client state")
	}
	_, _, writer, _ := prepareUDPSession(owner, context.Background(), M.SocksaddrFromNetIP(client), staleState)

	// 模擬 TTL 週期：清掃刪掉舊狀態，之後新封包重建一份並重新綁定。
	owner.table.delete(client, staleState)
	freshState := owner.table.loadOrCreate(client)
	if freshState == staleState {
		t.Fatal("expected a new client state")
	}
	owner.table.setBinding(client, destination, redirectAddress, false)

	buffer := buf.NewPacket()
	buffer.WriteString("late")
	defer buffer.Release()
	if err := writer.WritePacket(buffer, M.SocksaddrFromNetIP(destination)); err != nil {
		t.Fatalf("session writer did not follow the recreated state: %s", err)
	}
	replies := owner.recorded()
	if len(replies) != 1 {
		t.Fatalf("expected one recorded reply, got %d", len(replies))
	}
	if replies[0].state != freshState {
		t.Fatal("session writer used the stale client state")
	}
}

func TestPrepareUDPSessionCreatesMissingClientState(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:53111")
	owner := &fakeUDPSessionOwner{}
	ok, sessionContext, writer, onClose := prepareUDPSession(
		owner,
		context.Background(),
		M.SocksaddrFromNetIP(client),
		nil,
	)
	if !ok {
		t.Fatal("prepare did not accept the session")
	}
	if sessionContext == nil {
		t.Fatal("prepare returned no session context")
	}
	if onClose != nil {
		t.Fatal("eBPF sessions do not use the udpnat2 close handler")
	}
	sessionWriter, isSessionWriter := writer.(*udpSessionWriter)
	if !isSessionWriter {
		t.Fatalf("unexpected writer type %T", writer)
	}
	clientState, loaded := owner.table.load(client)
	if !loaded {
		t.Fatal("prepare did not create the client state")
	}
	if sessionWriter.captured != clientState {
		t.Fatal("session writer captured a different client state")
	}
}

type recordedUDPPacket struct {
	source      M.Socksaddr
	destination M.Socksaddr
	data        string
}

type sessionCountHandler struct {
	access   sync.Mutex
	sessions int
	sources  []M.Socksaddr
	packets  chan recordedUDPPacket
	finished chan struct{}
}

func (h *sessionCountHandler) prepare(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return true, context.Background(), &countingSessionWriter{}, nil
}

func (h *sessionCountHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.access.Lock()
	h.sessions++
	h.sources = append(h.sources, source)
	h.access.Unlock()
	defer func() {
		h.finished <- struct{}{}
	}()
	for {
		buffer := buf.NewPacket()
		packetDestination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		h.packets <- recordedUDPPacket{
			source:      source,
			destination: packetDestination,
			data:        string(buffer.Bytes()),
		}
		buffer.Release()
	}
}

func (h *sessionCountHandler) sessionCount() int {
	h.access.Lock()
	defer h.access.Unlock()
	return h.sessions
}

type countingSessionWriter struct{}

func (w *countingSessionWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

// TestUDPNatKeepsOneSessionPerClient 是這件架構債的核心驗收：
// 同一個 client 的多個 datagram 只能有一條 RoutePacketConnection，
// 但每一包仍要帶著自己的原目的地，否則回包的綁定查照會錯。
func TestUDPNatKeepsOneSessionPerClient(t *testing.T) {
	handler := &sessionCountHandler{
		packets:  make(chan recordedUDPPacket, 8),
		finished: make(chan struct{}, 4),
	}
	service := udpnat.New(handler, handler.prepare, time.Minute, false)
	client := M.SocksaddrFromNetIP(netip.MustParseAddrPort("127.0.0.1:41000"))
	otherClient := M.SocksaddrFromNetIP(netip.MustParseAddrPort("127.0.0.1:41001"))
	firstDestination := M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.7:443"))
	secondDestination := M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.9:443"))

	service.NewPacket([][]byte{[]byte("one")}, client, firstDestination, nil)
	service.NewPacket([][]byte{[]byte("two")}, client, secondDestination, nil)
	service.NewPacket([][]byte{[]byte("three")}, client, firstDestination, nil)
	service.NewPacket([][]byte{[]byte("four")}, otherClient, firstDestination, nil)

	var received []recordedUDPPacket
	for range 4 {
		select {
		case packet := <-handler.packets:
			received = append(received, packet)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for UDP session packets")
		}
	}
	if handler.sessionCount() != 2 {
		t.Fatalf("expected one session per client, got %d", handler.sessionCount())
	}

	// 不同 client 的 session 是不同 goroutine，跨 session 的送達順序不保證，
	// 只比同一條 session 內的順序與每一包的目的地。
	type sessionExpectation struct {
		source      M.Socksaddr
		destination M.Socksaddr
		data        string
	}
	expected := map[netip.AddrPort][]sessionExpectation{
		client.AddrPort(): {
			{client, firstDestination, "one"},
			{client, secondDestination, "two"},
			{client, firstDestination, "three"},
		},
		otherClient.AddrPort(): {
			{otherClient, firstDestination, "four"},
		},
	}
	receivedBySource := make(map[netip.AddrPort][]recordedUDPPacket)
	for _, packet := range received {
		receivedBySource[packet.source.AddrPort()] = append(receivedBySource[packet.source.AddrPort()], packet)
	}
	for source, want := range expected {
		got := receivedBySource[source]
		if len(got) != len(want) {
			t.Fatalf("source %s: got %d packets, want %d", source, len(got), len(want))
		}
		for index, expectation := range want {
			if got[index].source != expectation.source ||
				got[index].destination != expectation.destination ||
				got[index].data != expectation.data {
				t.Fatalf("source %s packet %d: got %+v want %+v", source, index, got[index], expectation)
			}
		}
	}

	// 收工：Purge 會關掉每條 session 的 doneChan，讀迴圈才不會留 goroutine。
	service.Purge()
	for range 2 {
		select {
		case <-handler.finished:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for UDP sessions to finish")
		}
	}
}

// TestUDPNatPurgeExpiredEnforcesTimeout 記錄為什麼兩個週期迴圈都要自己掃：
// freelru 命中既有 session 時只續期、不檢查逾期，不掃的話逾期的 client
// 會被重複使用，session 永遠不關。
func TestUDPNatPurgeExpiredEnforcesTimeout(t *testing.T) {
	handler := &sessionCountHandler{
		packets:  make(chan recordedUDPPacket, 8),
		finished: make(chan struct{}, 4),
	}
	timeout := 50 * time.Millisecond
	service := udpnat.New(handler, handler.prepare, timeout, false)
	client := M.SocksaddrFromNetIP(netip.MustParseAddrPort("127.0.0.1:41000"))
	destination := M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.7:443"))

	service.NewPacket([][]byte{[]byte("one")}, client, destination, nil)
	select {
	case <-handler.packets:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first UDP session packet")
	}
	time.Sleep(4 * timeout)
	service.PurgeExpired()
	service.NewPacket([][]byte{[]byte("two")}, client, destination, nil)
	select {
	case <-handler.packets:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the second UDP session packet")
	}
	if handler.sessionCount() != 2 {
		t.Fatalf("expected an expired session to be replaced, got %d sessions", handler.sessionCount())
	}
	service.Purge()
	for range 2 {
		select {
		case <-handler.finished:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for UDP sessions to finish")
		}
	}
}
