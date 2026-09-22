package conntrack

import (
	"context"
	"net"
	"sync"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Dialer owns a transport's sockets, including connections still being dialed.
// Reset permits later dials; Close also prevents new dials on a retired transport.
type Dialer struct {
	N.Dialer
	mu          sync.Mutex
	epoch       context.Context
	cancel      context.CancelFunc
	connections map[*ownedConn]struct{}
	closed      bool
}

func (d *Dialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	if d.epoch == nil {
		d.epoch, d.cancel = context.WithCancel(context.Background())
	}
	epoch := d.epoch
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(epoch, cancel)
	d.mu.Unlock()
	conn, err := d.Dialer.DialContext(dialCtx, network, address)
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	owned := &ownedConn{Conn: conn, owner: d, cancel: cancel, stop: stop}
	d.mu.Lock()
	if d.closed || epoch != d.epoch || epoch.Err() != nil {
		d.mu.Unlock()
		owned.Close()
		return nil, net.ErrClosed
	}
	if d.connections == nil {
		d.connections = make(map[*ownedConn]struct{})
	}
	d.connections[owned] = struct{}{}
	d.mu.Unlock()
	return owned, nil
}

func (d *Dialer) Reset() { d.close(false) }

func (d *Dialer) Close() error {
	d.close(true)
	return nil
}

func (d *Dialer) close(permanent bool) {
	d.mu.Lock()
	d.closed = d.closed || permanent
	cancel := d.cancel
	connections := d.connections
	d.epoch, d.cancel, d.connections = nil, nil, nil
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for conn := range connections {
		conn.Close()
	}
}

type ownedConn struct {
	net.Conn
	owner  *Dialer
	cancel context.CancelFunc
	stop   func() bool
	once   sync.Once
	err    error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() {
		c.stop()
		c.cancel()
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return c.err
}

func (c *ownedConn) Upstream() any { return c.Conn }
