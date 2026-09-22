package amneziawg

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

type testDialer struct{}

func (testDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (testDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", destination.String())
}

func TestClientBindPreservesMagicHeaders(t *testing.T) {
	for _, reserved := range [][3]byte{{}, {9, 8, 7}} {
		t.Run(string([]byte{'0' + reserved[0]}), func(t *testing.T) {
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err = server.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			address := server.LocalAddr().(*net.UDPAddr).AddrPort()
			bind := NewClientBind(context.Background(), log.StdLogger(), testDialer{}, true, address, reserved)
			defer bind.Close()
			if _, _, err = bind.Open(0); err != nil {
				t.Fatal(err)
			}
			packet := []byte{0x9e, 0x43, 0xd8, 0x51, 5, 6, 7, 8}
			original := append([]byte(nil), packet...)
			if err = bind.Send([][]byte{packet}, remoteEndpoint(address)); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, 128)
			n, peer, err := server.ReadFrom(received)
			if err != nil {
				t.Fatal(err)
			}
			expected := append([]byte(nil), original...)
			if reserved != [3]byte{} {
				copy(expected[1:4], reserved[:])
			}
			if !bytes.Equal(expected, received[:n]) {
				t.Fatalf("sent header changed: %x", received[:n])
			}
			if _, err = server.WriteTo(received[:n], peer); err != nil {
				t.Fatal(err)
			}
			packets := [][]byte{make([]byte, 128)}
			sizes := make([]int, 1)
			endpoints := make([]conn.Endpoint, 1)
			if _, err = bind.receive(packets, sizes, endpoints); err != nil {
				t.Fatal(err)
			}
			if reserved != [3]byte{} {
				clear(expected[1:4])
			}
			if !bytes.Equal(expected, packets[0][:sizes[0]]) {
				t.Fatalf("received header changed: %x", packets[0][:sizes[0]])
			}
		})
	}
}

func TestEndpointRejectsInvalidKeysAndParameterInjection(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := []EndpointOptions{
		{PrivateKey: "AA=="},
		{PrivateKey: key, InitPacketMagicHeader: "64\nreplace_peers=true"},
		{PrivateKey: key, SpecialJunk1: "<r 16>\rprivate_key=0"},
		{PrivateKey: key, Peers: []PeerOptions{{PublicKey: "AA=="}}},
		{PrivateKey: key, Peers: []PeerOptions{{PublicKey: key, PreSharedKey: "AA=="}}},
		{PrivateKey: key, JunkPacketCount: 1, Peers: []PeerOptions{{PublicKey: key, Reserved: []byte{1, 2, 3}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}},
	}
	for index, options := range cases {
		_, err := NewEndpoint(options)
		if err == nil {
			t.Fatalf("case %d accepted", index)
		}
		if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "replace_peers") {
			t.Fatalf("case %d exposed input", index)
		}
	}
}
