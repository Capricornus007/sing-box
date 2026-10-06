package conntrack

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type testDialerFunc func(context.Context) (net.Conn, error)

func (f testDialerFunc) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return f(ctx)
}
func (f testDialerFunc) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestDialerResetClosesActiveConnectionsAndAllowsReconnect(t *testing.T) {
	var peers []net.Conn
	dialer := &Dialer{Dialer: testDialerFunc(func(context.Context) (net.Conn, error) {
		client, peer := net.Pipe()
		peers = append(peers, peer)
		return client, nil
	})}
	defer dialer.Close()
	defer func() {
		for _, peer := range peers {
			peer.Close()
		}
	}()
	first, err := dialer.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	dialer.Reset()
	if _, err = first.Write([]byte{1}); err == nil {
		t.Fatal("active connection survived reset")
	}
	second, err := dialer.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	if len(dialer.connections) != 0 {
		t.Fatal("closed connection retained")
	}
	if err = dialer.Close(); err != nil {
		t.Fatal(err)
	}
	dialer.Reset()
	if _, err = dialer.DialContext(context.Background(), "tcp", M.Socksaddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("retired dialer reopened", err)
	}
}

func TestDialerResetCancelsPendingDial(t *testing.T) {
	entered := make(chan struct{})
	dialer := &Dialer{Dialer: testDialerFunc(func(ctx context.Context) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})}
	defer dialer.Close()
	result := make(chan error, 1)
	go func() {
		_, err := dialer.DialContext(context.Background(), "tcp", M.Socksaddr{})
		result <- err
	}()
	<-entered
	dialer.Reset()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending dial was not canceled")
	}
}

func TestDialerDiscardsConnectionCompletedAfterReset(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	client, peer := net.Pipe()
	defer peer.Close()
	dialer := &Dialer{Dialer: testDialerFunc(func(context.Context) (net.Conn, error) {
		close(entered)
		<-release
		return client, nil
	})}
	defer dialer.Close()
	result := make(chan error, 1)
	go func() {
		_, err := dialer.DialContext(context.Background(), "tcp", M.Socksaddr{})
		result <- err
	}()
	<-entered
	dialer.Reset()
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late dial did not return")
	}
	if _, err := client.Write([]byte{1}); err == nil {
		t.Fatal("late connection remained open")
	}
}
