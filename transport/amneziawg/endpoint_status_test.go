//go:build with_gvisor

package amneziawg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"

	"golang.org/x/crypto/curve25519"
)

type testKey struct {
	private string
	public  string
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)}
}

// listenDialer hands the bind a socket on a fixed local address, so a peer can be told where
// to send its handshake.
type listenDialer struct {
	testDialer
	address string
}

func (d listenDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", d.address)
}

func newTestEndpoint(t *testing.T, ctx context.Context, dialer N.Dialer, key string, address []netip.Prefix, peers []PeerOptions) *Endpoint {
	t.Helper()
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Dialer:     dialer,
		Address:    address,
		PrivateKey: key,
		Peers:      peers,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { endpoint.Close() })
	return endpoint
}

func freeUDPAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().String()
	conn.Close()
	return address
}

func TestEndpointStatusLifecycle(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	serverKey, keepaliveKey, idleKey := newTestKey(t), newTestKey(t), newTestKey(t)
	serverAddress := freeUDPAddress(t)
	server := newTestEndpoint(t, ctx, listenDialer{address: serverAddress}, serverKey.private,
		[]netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
		[]PeerOptions{
			{PublicKey: keepaliveKey.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}},
			{PublicKey: idleKey.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.3/32")}},
		})
	clientPeer := func(keepalive uint16) []PeerOptions {
		return []PeerOptions{{
			Endpoint:                    M.ParseSocksaddr(serverAddress),
			PublicKey:                   serverKey.public,
			AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")},
			PersistentKeepaliveInterval: keepalive,
		}}
	}
	keepalive := newTestEndpoint(t, ctx, testDialer{}, keepaliveKey.private,
		[]netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}, clientPeer(1))
	idle := newTestEndpoint(t, ctx, testDialer{}, idleKey.private,
		[]netip.Prefix{netip.MustParsePrefix("10.77.0.3/32")}, clientPeer(0))

	if _, err := keepalive.PeerStatus(); err == nil {
		t.Fatal("status must be unavailable before start")
	}
	for _, endpoint := range []*Endpoint{server, keepalive, idle} {
		if err := endpoint.Start(false); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing is sent through either tunnel: only an applied keepalive starts a handshake.
	var status PeerStatus
	deadline := time.Now().Add(10 * time.Second)
	for {
		peers, err := keepalive.PeerStatus()
		if err != nil {
			t.Fatal(err)
		}
		if len(peers) != 1 {
			t.Fatalf("got %d peers", len(peers))
		}
		status = peers[0]
		if !status.LastHandshake.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("keepalive did not start a handshake")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status.PublicKey != serverKey.public || status.Endpoint != serverAddress {
		t.Fatalf("unexpected peer identity: %+v", status)
	}
	if status.PersistentKeepaliveInterval != 1 || status.TxBytes == 0 || status.RxBytes == 0 {
		t.Fatalf("unexpected peer state: %+v", status)
	}
	if !slices.Equal(status.AllowedIPs, []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}) {
		t.Fatalf("allowed IPs %v", status.AllowedIPs)
	}
	idlePeers, err := idle.PeerStatus()
	if err != nil {
		t.Fatal(err)
	}
	if len(idlePeers) != 1 || !idlePeers[0].LastHandshake.IsZero() || idlePeers[0].PersistentKeepaliveInterval != 0 {
		t.Fatalf("a peer without traffic or keepalive must not report a handshake: %+v", idlePeers)
	}

	keepalive.Close()
	if _, err = keepalive.PeerStatus(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("status after close: %v", err)
	}
}

func TestEndpointRejectsDestinationsOutsideAllowedIPs(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	address := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("fd00::2/128")}
	v4, v6 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")
	destination := M.ParseSocksaddrHostPort("service.example", 53)
	for _, testCase := range []struct {
		name      string
		allowed   []netip.Prefix
		addresses []netip.Addr
		want      netip.Addr
		rejected  netip.Addr
	}{
		{"ipv4 only", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []netip.Addr{v6, v4}, v4, v6},
		{"ipv6 only", []netip.Prefix{netip.MustParsePrefix("fd00::/8")}, []netip.Addr{v4, v6}, v6, v4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			endpoint := newTestEndpoint(t, ctx, testDialer{}, newTestKey(t).private, address, []PeerOptions{{
				Endpoint:   M.ParseSocksaddr("192.0.2.1:51820"),
				PublicKey:  newTestKey(t).public,
				AllowedIPs: testCase.allowed,
			}})
			if !slices.Equal(endpoint.allowedAddress, testCase.allowed) {
				t.Fatalf("device routes changed: %v", endpoint.allowedAddress)
			}
			_, err := endpoint.DialContext(ctx, N.NetworkUDP, M.SocksaddrFrom(testCase.rejected, 53))
			if err == nil || !strings.Contains(err.Error(), "outside the allowed IPs") {
				t.Fatalf("dial outside the allowed IPs: %v", err)
			}
			if _, err = endpoint.ListenPacket(ctx, M.SocksaddrFrom(testCase.rejected, 53)); err == nil {
				t.Fatal("listen outside the allowed IPs must fail")
			}
			conn, err := N.DialSerial(ctx, endpoint, N.NetworkUDP, destination, testCase.addresses)
			if err != nil {
				t.Fatal(err)
			}
			remote := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap().Addr
			conn.Close()
			if remote != testCase.want {
				t.Fatalf("serial dial chose %s, want %s", remote, testCase.want)
			}
			packetConn, chosen, err := N.ListenSerial(ctx, endpoint, destination, testCase.addresses)
			if err != nil {
				t.Fatal(err)
			}
			packetConn.Close()
			if chosen != testCase.want {
				t.Fatalf("serial listen chose %s, want %s", chosen, testCase.want)
			}
		})
	}
}
