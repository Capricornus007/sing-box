//go:build with_gvisor

package amneziawg

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"
)

// udpRelay stands in for the network behind a WireGuard server: it forwards each UDP packet
// arriving through the tunnel to the real socket mapped to its destination address, and sends
// the replies back through the tunnel from that destination.
type udpRelay struct {
	targets  map[netip.Addr]string
	received atomic.Int32
	replies  atomic.Int32
}

func (r *udpRelay) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (r *udpRelay) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
}

func (r *udpRelay) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func (r *udpRelay) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if onClose != nil {
		defer onClose(nil)
	}
	defer conn.Close()
	var access sync.Mutex
	sockets := make(map[M.Socksaddr]net.Conn)
	defer func() {
		access.Lock()
		for _, socket := range sockets {
			socket.Close()
		}
		access.Unlock()
	}()
	for {
		buffer := buf.NewPacket()
		packetDestination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		r.received.Add(1)
		target, routed := r.targets[packetDestination.Addr]
		if !routed {
			buffer.Release()
			continue
		}
		access.Lock()
		socket := sockets[packetDestination]
		if socket == nil {
			socket, err = net.Dial("udp", target)
			if err != nil {
				access.Unlock()
				buffer.Release()
				return
			}
			sockets[packetDestination] = socket
			go func(socket net.Conn, from M.Socksaddr) {
				reply := make([]byte, 65535)
				for {
					n, err := socket.Read(reply)
					if err != nil {
						return
					}
					r.replies.Add(1)
					packet := buf.NewPacket()
					packet.Write(reply[:n])
					if conn.WritePacket(packet, from) != nil {
						return
					}
				}
			}(socket, packetDestination)
		}
		access.Unlock()
		socket.Write(buffer.Bytes())
		buffer.Release()
	}
}

// A multi-peer WireGuard detoured through a WireGuard with split AllowedIPs opens one
// unconnected socket on the outer endpoint. The bind hint must pass while concrete
// destinations stay limited to the outer peer's routes.
func TestMultiPeerWireGuardThroughSplitWireGuard(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	outerServerKey, outerClientKey := newTestKey(t), newTestKey(t)
	innerKey, innerServerA, innerServerB, unroutedKey := newTestKey(t), newTestKey(t), newTestKey(t), newTestKey(t)
	innerAddress := []netip.Prefix{netip.MustParsePrefix("10.95.0.2/32")}
	innerServer := func(key testKey, address string, tunnelAddress string) *Endpoint {
		return newTestEndpoint(t, ctx, listenDialer{address: address}, key.private,
			[]netip.Prefix{netip.MustParsePrefix(tunnelAddress)},
			[]PeerOptions{{PublicKey: innerKey.public, AllowedIPs: innerAddress}})
	}
	realA, realB := freeUDPAddress(t), freeUDPAddress(t)
	serverA := innerServer(innerServerA, realA, "10.91.0.1/32")
	serverB := innerServer(innerServerB, realB, "10.92.0.1/32")

	outerServerAddress := freeUDPAddress(t)
	relay := &udpRelay{targets: map[netip.Addr]string{netip.MustParseAddr("10.90.0.5"): realA, netip.MustParseAddr("10.90.0.6"): realB}}
	outerServer, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Dialer:     listenDialer{address: outerServerAddress},
		Handler:    relay,
		UDPTimeout: time.Minute,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.90.0.1/32")},
		PrivateKey: outerServerKey.private,
		Peers:      []PeerOptions{{PublicKey: outerClientKey.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.90.0.2/32")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outerServer.Close() })
	outerClient := newTestEndpoint(t, ctx, testDialer{}, outerClientKey.private,
		[]netip.Prefix{netip.MustParsePrefix("10.90.0.2/32")},
		[]PeerOptions{{
			Endpoint:   M.ParseSocksaddr(outerServerAddress),
			PublicKey:  outerServerKey.public,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.90.0.0/24")},
		}})
	inner := newTestEndpoint(t, ctx, outerClient, innerKey.private, innerAddress, []PeerOptions{
		{Endpoint: M.ParseSocksaddr("10.90.0.5:51820"), PublicKey: innerServerA.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.91.0.0/24")}, PersistentKeepaliveInterval: 1},
		{Endpoint: M.ParseSocksaddr("10.90.0.6:51820"), PublicKey: innerServerB.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.92.0.0/24")}, PersistentKeepaliveInterval: 1},
		// Outside the outer peer's AllowedIPs: its packets must never leave the outer tunnel.
		{Endpoint: M.ParseSocksaddr("10.99.0.1:51820"), PublicKey: unroutedKey.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.93.0.0/24")}, PersistentKeepaliveInterval: 1},
	})
	for _, endpoint := range []*Endpoint{serverA, serverB, outerServer, outerClient, inner} {
		if err = endpoint.Start(false); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(20 * time.Second)
	var peers []PeerStatus
	for {
		peers, err = inner.PeerStatus()
		if err != nil {
			t.Fatal(err)
		}
		if len(peers) != 3 {
			t.Fatalf("got %d peers", len(peers))
		}
		handshakes := map[string]bool{}
		for _, peer := range peers {
			handshakes[peer.PublicKey] = !peer.LastHandshake.IsZero()
		}
		if handshakes[innerServerA.public] && handshakes[innerServerB.public] {
			if handshakes[unroutedKey.public] {
				t.Fatal("a peer outside the outer AllowedIPs completed a handshake")
			}
			break
		}
		if time.Now().After(deadline) {
			outerPeers, _ := outerClient.PeerStatus()
			serverPeers, _ := outerServer.PeerStatus()
			t.Fatalf("inner peers did not complete handshakes through the outer tunnel: %+v\nouter client %+v\nouter server %+v\nrelay received %d, replies %d",
				peers, outerPeers, serverPeers, relay.received.Load(), relay.replies.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}

	if _, err = outerClient.ListenPacket(ctx, M.SocksaddrFrom(netip.MustParseAddr("10.99.0.1"), 51820)); err == nil {
		t.Fatal("a concrete destination outside the AllowedIPs must still be rejected")
	}
	if _, err = outerClient.DialContext(ctx, N.NetworkUDP, M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 53)); err == nil {
		t.Fatal("dial outside the AllowedIPs must still be rejected")
	}
	if _, err = outerClient.ListenPacket(ctx, M.Socksaddr{}); err == nil {
		t.Fatal("a missing destination must still be rejected")
	}
	packetConn, err := outerClient.ListenPacket(ctx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
	if err != nil {
		t.Fatal("bind hint: ", err)
	}
	packetConn.Close()
}
