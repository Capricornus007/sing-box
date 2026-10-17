//go:build with_gvisor

package amneziawg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"
)

func v31Options(key string, address string, peers []PeerOptions, dialer N.Dialer, headerKey string) EndpointOptions {
	return EndpointOptions{
		Context:    pause.WithDefaultManager(context.Background()),
		Logger:     log.NewNOPFactory().Logger(),
		Dialer:     dialer,
		Address:    []netip.Prefix{netip.MustParsePrefix(address)},
		PrivateKey: key,
		Peers:      peers,
		AmneziaWGObfuscationOptions: option.AmneziaWGObfuscationOptions{
			JunkPacketCount:        3,
			JunkPacketMinSize:      40,
			JunkPacketMaxSize:      90,
			InitPacketJunkSize:     20,
			ResponsePacketJunkSize: 30,
			// Header protection needs every junk size of at least 12 bytes.
			CookieReplyPacketJunkSize:  20,
			TransportPacketJunkSize:    16,
			InitPacketMagicHeader:      "100000-800000",
			ResponsePacketMagicHeader:  "1000000-8000000",
			UnderloadPacketMagicHeader: "10000000-80000000",
			TransportPacketMagicHeader: "100000000-800000000",
			HeaderProtectionKey:        headerKey,
			ContentPaddingAddition:     "8-24",
			RekeyAfterTime:             "110-130",
			RejectAfterTime:            "170-200",
			RandomTrailers:             true,
		},
	}
}

func TestAmneziaWG31Handshake(t *testing.T) {
	newHeaderKey := func() string {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		return base64.StdEncoding.EncodeToString(key)
	}
	shared := newHeaderKey()
	for name, clientHeaderKey := range map[string]string{"matching key": shared, "other key": newHeaderKey()} {
		t.Run(name, func(t *testing.T) {
			serverKey, clientKey := newTestKey(t), newTestKey(t)
			serverAddress := freeUDPAddress(t)
			server, err := NewEndpoint(v31Options(serverKey.private, "10.79.0.1/32",
				[]PeerOptions{{PublicKey: clientKey.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.79.0.2/32")}}},
				listenDialer{address: serverAddress}, shared))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := NewEndpoint(v31Options(clientKey.private, "10.79.0.2/32",
				[]PeerOptions{{
					Endpoint:                    M.ParseSocksaddr(serverAddress),
					PublicKey:                   serverKey.public,
					AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("10.79.0.0/24")},
					PersistentKeepaliveInterval: 1,
				}}, testDialer{}, clientHeaderKey))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for _, endpoint := range []*Endpoint{server, client} {
				if err = endpoint.Start(false); err != nil {
					t.Fatal(err)
				}
			}
			handshake := false
			for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline) && !handshake; time.Sleep(50 * time.Millisecond) {
				peers, err := client.PeerStatus()
				if err != nil {
					t.Fatal(err)
				}
				handshake = len(peers) == 1 && !peers[0].LastHandshake.IsZero()
			}
			if handshake != (clientHeaderKey == shared) {
				t.Fatalf("handshake %v with %s", handshake, name)
			}
		})
	}
}

func TestAmneziaWG31OptionsReachTheDevice(t *testing.T) {
	peers := []PeerOptions{{Endpoint: M.ParseSocksaddr("127.0.0.1:1"), PublicKey: newTestKey(t).public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.79.0.0/24")}}}
	options := v31Options(newTestKey(t).private, "10.79.0.2/32", peers, testDialer{}, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	endpoint, err := NewEndpoint(options)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Close()
	lines, err := IpcLines(options.AmneziaWGObfuscationOptions)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"header_protection_key=" + strings.Repeat("00", 32), "content_padding_addition=8-24", "rekey_after_time=110-130", "reject_after_time=170-200", "random_trailers=true"} {
		if !strings.Contains(lines, line+"\n") {
			t.Fatalf("missing %s in %q", line, lines)
		}
	}
	for _, bad := range []string{"short", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		options.HeaderProtectionKey = bad
		if _, err := NewEndpoint(options); err == nil {
			t.Fatalf("accepted header protection key %q", bad)
		}
	}
	options.HeaderProtectionKey = ""
	options.RekeyTimeout = "5\nprivate_key=00"
	if _, err := NewEndpoint(options); err == nil {
		t.Fatal("accepted a line break")
	}
}
