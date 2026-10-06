package snell

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

type quicTestConn struct {
	net.Conn
	writes int
}

func (c *quicTestConn) Write(b []byte) (int, error) { c.writes++; return len(b), nil }
func (*quicTestConn) Close() error                  { return nil }

type quicTestDialer struct {
	networks    []string
	connections []*quicTestConn
}

func (d *quicTestDialer) DialContext(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	conn := new(quicTestConn)
	d.networks = append(d.networks, network)
	d.connections = append(d.connections, conn)
	return conn, nil
}

func (*quicTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestV5QUICProxyDispatchSurvivesReconnect(t *testing.T) {
	dialer := new(quicTestDialer)
	outbound := &Outbound{dialer: dialer, version: 5, psk: []byte("example-password"), logger: log.NewNOPFactory().Logger()}
	source, destination := M.ParseSocksaddr("192.0.2.10:10000"), M.ParseSocksaddr("198.51.100.20:443")
	for _, protocol := range []string{C.ProtocolQUIC, ""} {
		ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{Source: source, Protocol: protocol})
		conn, err := outbound.ListenPacket(ctx, destination)
		if err != nil {
			t.Fatal(err)
		}
		// A resumed short header needs the sniff result or the cached QUIC mode.
		payload := []byte{0x40, 1, 2, 3}
		if n, err := conn.WriteTo(payload, destination); err != nil || n != len(payload) {
			t.Fatal(n, err)
		}
		conn.Close()
		if !outbound.isRecentQUICDest(source, destination) {
			t.Fatal("QUIC mode was not cached")
		}
	}
	if len(dialer.networks) != 2 {
		t.Fatal("unexpected dial count", dialer.networks)
	}
	for i, network := range dialer.networks {
		if network != "udp" {
			t.Fatal("QUIC proxy fell back to TCP", network)
		}
		if dialer.connections[i].writes != 1 {
			t.Fatal("initial QUIC payload sent more than once")
		}
	}
	if outbound.isRecentQUICDest(M.ParseSocksaddr("192.0.2.11:10000"), destination) {
		t.Fatal("another source inherited the QUIC mode")
	}
}
