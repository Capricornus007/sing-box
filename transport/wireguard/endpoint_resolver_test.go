package wireguard

import (
	"net/netip"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
)

func TestEndpointResolverRoutesByPeerKey(t *testing.T) {
	keyHex := strings.Repeat("01", 32)
	var key device.NoisePublicKey
	if err := key.FromHex(keyHex); err != nil {
		t.Fatal(err)
	}
	calls := 0
	endpoint := &Endpoint{
		options: EndpointOptions{ResolvePeer: func(domain string) ([]netip.Addr, error) {
			calls++
			if domain != "peer.example" {
				t.Fatal("wrong peer domain")
			}
			return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, nil
		}},
		peers: []peerConfig{{publicKey: key, destination: M.ParseSocksaddr("peer.example:51820")}},
	}
	resolver, err := endpoint.endpointResolver(conn.NewStdNetBind(nil))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver(key)
	if err != nil || len(resolved) != 2 {
		t.Fatal("missing candidates", err)
	}
	if resolved[0].DstToString() != "192.0.2.1:51820" || resolved[1].DstToString() != "[2001:db8::1]:51820" {
		t.Fatal("wrong candidate endpoints")
	}
	if result, err := resolver(device.NoisePublicKey{}); err != nil || len(result) != 0 || calls != 1 {
		t.Fatal("unknown peer performed a lookup")
	}
}
