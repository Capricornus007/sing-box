package amneziawg

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParsePeerStatusCopiesOnlyAllowlistedFields(t *testing.T) {
	const (
		privateKey   = "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
		presharedKey = "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52"
	)
	state := strings.Join([]string{
		"private_key=" + privateKey,
		"listen_port=51820",
		"jc=4",
		"public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33",
		"preshared_key=" + presharedKey,
		"protocol_version=1",
		"endpoint=192.0.2.1:51820",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=500",
		"tx_bytes=10",
		"rx_bytes=20",
		"persistent_keepalive_interval=25",
		"allowed_ip=10.0.0.0/8",
		"allowed_ip=fd00::/8",
		"public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376",
		"preshared_key=0000000000000000000000000000000000000000000000000000000000000000",
		"protocol_version=1",
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"tx_bytes=0",
		"rx_bytes=0",
		"allowed_ip=192.168.4.0/24",
		"",
	}, "\n")

	peers := parsePeerStatus(state)

	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(peers))
	}
	first := peers[0]
	if first.PublicKey != "uFmW/sycfx/G0lcqdu2hHVm80gvo5UOxXOS9hajnWjM=" {
		t.Fatalf("public key %q", first.PublicKey)
	}
	if first.Endpoint != "192.0.2.1:51820" || first.TxBytes != 10 || first.RxBytes != 20 {
		t.Fatalf("unexpected counters or endpoint: %+v", first)
	}
	if !first.LastHandshake.Equal(time.Unix(1700000000, 500)) {
		t.Fatalf("last handshake %v", first.LastHandshake)
	}
	if first.PersistentKeepaliveInterval != 25 {
		t.Fatalf("keepalive %d", first.PersistentKeepaliveInterval)
	}
	if fmt.Sprint(first.AllowedIPs) != "[10.0.0.0/8 fd00::/8]" {
		t.Fatalf("allowed IPs %v", first.AllowedIPs)
	}
	second := peers[1]
	if !second.LastHandshake.IsZero() || second.Endpoint != "" || second.PersistentKeepaliveInterval != 0 {
		t.Fatalf("a peer without a handshake must report the zero time: %+v", second)
	}
	if fmt.Sprint(second.AllowedIPs) != fmt.Sprint([]netip.Prefix{netip.MustParsePrefix("192.168.4.0/24")}) {
		t.Fatalf("allowed IPs %v", second.AllowedIPs)
	}
	dump := fmt.Sprintf("%+v", peers)
	for _, secret := range []string{privateKey, presharedKey, "6EtabScXwQA6E7QxVwNT26ypFGzxUMX4V1aA/rpSAno=", "GIUVCT6VL18i6GXO8wEucvi18LWYrAMJ1drM47cPz1I="} {
		if strings.Contains(dump, secret) {
			t.Fatal("status leaked key material")
		}
	}
}
