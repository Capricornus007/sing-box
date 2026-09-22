package shadowsocksr

import (
	"net"
	"testing"
)

type inputPacketConn struct {
	net.PacketConn
	packet []byte
}

func (c inputPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return copy(b, c.packet), nil, nil
}

func TestPacketReadRemovesOnlyTheAddressPrefix(t *testing.T) {
	conn := ssPacketConn{PacketConn: inputPacketConn{packet: []byte{1, 192, 0, 2, 1, 0, 53, 'o', 'k'}}}
	b := make([]byte, 64)
	n, addr, err := conn.ReadFrom(b)
	if err != nil || n != 2 || string(b[:n]) != "ok" || addr.String() != "192.0.2.1:53" {
		t.Fatal(n, addr, err)
	}
	conn.PacketConn = inputPacketConn{packet: []byte{1, 192, 0, 2}}
	if _, _, err := conn.ReadFrom(b); err == nil {
		t.Fatal("truncated address accepted")
	}
}
