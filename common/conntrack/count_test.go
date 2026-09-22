package conntrack

import (
	"net"
	"sync"
	"testing"
)

type noOpPacketConn struct{ net.PacketConn }

func (noOpPacketConn) Close() error { return nil }

func TestCountWhileConnectionsClose(t *testing.T) {
	if !Enabled {
		t.Skip("connection tracking disabled")
	}
	previousEnabled, previousLimit := KillerEnabled, MemoryLimit
	KillerEnabled, MemoryLimit = true, ^uint64(0)
	defer func() { KillerEnabled, MemoryLimit = previousEnabled, previousLimit }()
	var work sync.WaitGroup
	for range 4 {
		work.Go(func() {
			for range 100 {
				raw, peer := net.Pipe()
				conn, err := NewConn(raw)
				if err != nil {
					t.Error(err)
					peer.Close()
					continue
				}
				packet, err := NewPacketConn(noOpPacketConn{})
				if err != nil {
					t.Error(err)
				} else {
					packet.Close()
				}
				Count()
				conn.Close()
				peer.Close()
			}
		})
	}
	work.Go(func() {
		for range 100 {
			Close()
			Count()
		}
	})
	work.Wait()
	if Count() != 0 {
		t.Fatal("closed connections retained")
	}
}
