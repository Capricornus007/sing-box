//go:build with_gvisor

package amneziawg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	wgconn "github.com/sagernet/wireguard-go/conn"
	wgdevice "github.com/sagernet/wireguard-go/device"
	"github.com/sagernet/wireguard-go/tun/tuntest"
)

// The WireGuard device of the Tailscale endpoint, given the same AmneziaWG settings, completes
// a handshake with the AmneziaWG device; with other settings or none, it does not.
func TestTailscaleDeviceSpeaksAmneziaWG(t *testing.T) {
	hexKey := func(key string) string {
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	// A nonzero key, so header protection is on.
	headerKey := base64.StdEncoding.EncodeToString(append(make([]byte, 31), 7))
	settings := v31Options("", "10.79.0.1/32", nil, testDialer{}, headerKey).AmneziaWGObfuscationOptions
	otherHeaders := settings
	otherHeaders.InitPacketMagicHeader = "900000-990000"
	for name, clientSettings := range map[string]struct {
		lines bool
		match bool
	}{
		"same settings":   {true, true},
		"plain WireGuard": {false, false},
		"other headers":   {true, false},
	} {
		t.Run(name, func(t *testing.T) {
			serverKey, clientKey := newTestKey(t), newTestKey(t)
			serverAddress := freeUDPAddress(t)
			server, err := NewEndpoint(v31Options(serverKey.private, "10.79.0.1/32",
				[]PeerOptions{{PublicKey: clientKey.public, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.79.0.2/32")}}},
				listenDialer{address: serverAddress}, headerKey))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err = server.Start(false); err != nil {
				t.Fatal(err)
			}

			lines := ""
			if clientSettings.lines {
				obfuscation := settings
				if name == "other headers" {
					obfuscation = otherHeaders
				}
				if lines, err = IpcLines(obfuscation); err != nil {
					t.Fatal(err)
				}
			}
			device := wgdevice.NewDevice(context.Background(), tuntest.NewChannelTUN().TUN(), &udpBind{}, wgdevice.NewLogger(wgdevice.LogLevelError, ""), 0)
			defer device.Close()
			err = device.IpcSet("private_key=" + hexKey(clientKey.private) + "\nlisten_port=0\n" + lines +
				"public_key=" + hexKey(serverKey.public) + "\nendpoint=" + serverAddress +
				"\nallowed_ip=10.79.0.1/32\npersistent_keepalive_interval=1\n")
			if err != nil {
				t.Fatal(err)
			}
			if err = device.Up(); err != nil {
				t.Fatal(err)
			}

			handshake := false
			for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline) && !handshake; time.Sleep(50 * time.Millisecond) {
				peers, err := server.PeerStatus()
				if err != nil {
					t.Fatal(err)
				}
				handshake = len(peers) == 1 && !peers[0].LastHandshake.IsZero()
			}
			if handshake != clientSettings.match {
				t.Fatalf("handshake %v with %s", handshake, name)
			}
		})
	}
}

// udpBind passes every byte through, as magicsock does for the Tailscale device. The standard
// bind clears bytes 1 to 3 of received packets for WARP's reserved field; with AmneziaWG padding
// those bytes belong to the header protection nonce.
type udpBind struct {
	conn *net.UDPConn
}

func (b *udpBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = conn
	receive := func(packets [][]byte, sizes []int, endpoints []wgconn.Endpoint) (int, error) {
		n, source, err := conn.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		endpoints[0] = &wgconn.StdNetEndpoint{AddrPort: source}
		return 1, nil
	}
	return []wgconn.ReceiveFunc{receive}, uint16(conn.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *udpBind) Close() error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *udpBind) SetMark(uint32) error { return nil }

func (b *udpBind) Send(buffers [][]byte, endpoint wgconn.Endpoint, offset int) error {
	for _, buffer := range buffers {
		if _, err := b.conn.WriteToUDPAddrPort(buffer[offset:], endpoint.(*wgconn.StdNetEndpoint).AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (b *udpBind) ParseEndpoint(s string) (wgconn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	return &wgconn.StdNetEndpoint{AddrPort: addrPort}, err
}

func (b *udpBind) BatchSize() int { return 1 }

func (b *udpBind) SetReservedForEndpoint(netip.AddrPort, [3]byte) {}
