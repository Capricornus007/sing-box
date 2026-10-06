package snell

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestCloseBeforeWriteUnblocksReadAndPreventsDial(t *testing.T) {
	dialer := new(quicTestDialer)
	conn := newV5LazyPacketConn(context.Background(), &Outbound{dialer: dialer}, M.Socksaddr{}, M.Socksaddr{}, true)
	result := make(chan error, 1)
	go func() { _, _, err := conn.ReadFrom(make([]byte, 16)); result <- err }()
	conn.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read was not released")
	}
	if _, err := conn.WriteTo([]byte{0xc0}, M.Socksaddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if len(dialer.networks) != 0 {
		t.Fatal("closed connection dialed")
	}
}
