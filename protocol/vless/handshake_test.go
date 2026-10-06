package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/vless/encryption"
	M "github.com/sagernet/sing/common/metadata"
)

type trackedHandshakeConn struct {
	net.Conn
	closed bool
}

func (c *trackedHandshakeConn) Close() error   { c.closed = true; return c.Conn.Close() }
func (*trackedHandshakeConn) Handshake() error { return nil }

type handshakeDialer struct{ conn net.Conn }

func (d handshakeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (handshakeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestFailedPacketEncryptionClosesOriginalConnection(t *testing.T) {
	raw, peer := net.Pipe()
	peer.Close()
	conn := &trackedHandshakeConn{Conn: raw}
	defer conn.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := new(encryption.ClientInstance)
	if err := client.Init([][]byte{key.PublicKey().Bytes()}, 0, 0, ""); err != nil {
		t.Fatal(err)
	}
	dialer := vlessDialer{dialer: handshakeDialer{conn}, encryption: client, logger: log.NewNOPFactory().Logger()}
	if _, err := dialer.ListenPacket(context.Background(), M.ParseSocksaddr("example.invalid:443")); err == nil {
		t.Fatal("handshake unexpectedly succeeded")
	}
	if !conn.closed {
		t.Fatal("failed handshake leaked its original connection")
	}
	if isVisionTLSConn(conn) {
		t.Fatal("a non-TLS handshake was classified as TLS")
	}
}
