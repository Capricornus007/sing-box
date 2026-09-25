package wireguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

var _ Device = (*stackDevice)(nil)

type stackDevice struct {
	stack        *tun.Go
	memoryTun    *tun.MemoryTun
	mtu          uint32
	events       chan wgTun.Event
	closeOnce    sync.Once
	closed       atomic.Bool
	closeSignal  chan struct{}
	inet4Address netip.Addr
	inet6Address netip.Addr
	outbound     stackOutbound
}

// stackOutbound bridges sing-tun's push-style memory TUN outbound handler to the
// pull-style batch read that wireguard-go's TUN device loop expects.
type stackOutbound struct {
	access   sync.Mutex
	pending  []*buf.Buffer
	wake     chan struct{}
	capacity int
}

func newStackDevice(options DeviceOptions) (*stackDevice, error) {
	device := &stackDevice{
		mtu:         options.MTU,
		events:      make(chan wgTun.Event, 1),
		closeSignal: make(chan struct{}),
		outbound: stackOutbound{
			wake:     make(chan struct{}, 1),
			capacity: conn.IdealBatchSize * memoryTunOutboundQueueBatches,
		},
	}
	device.inet4Address, device.inet6Address = deviceAddresses(options.Address)
	device.memoryTun = tun.NewMemoryTun(tun.MemoryTunOptions{
		MTU:      int(options.MTU),
		Outbound: device.enqueueOutbound,
	})
	var err error
	device.stack, err = newStack(options, device.memoryTun)
	if err != nil {
		return nil, err
	}
	return device, nil
}

// memoryTunOutboundQueueBatches bounds how many batches may pile up while the
// wireguard read loop is not draining; beyond it the oldest packets are dropped,
// because sing-tun has already handed ownership of these buffers to us.
const memoryTunOutboundQueueBatches = 4

func (w *stackDevice) enqueueOutbound(packetBuffers []*buf.Buffer) {
	w.outbound.access.Lock()
	if w.closed.Load() {
		w.outbound.access.Unlock()
		buf.ReleaseMulti(packetBuffers)
		return
	}
	available := w.outbound.capacity - len(w.outbound.pending)
	if available <= 0 {
		w.outbound.access.Unlock()
		buf.ReleaseMulti(packetBuffers)
		return
	}
	if len(packetBuffers) > available {
		buf.ReleaseMulti(packetBuffers[available:])
		packetBuffers = packetBuffers[:available]
	}
	w.outbound.pending = append(w.outbound.pending, packetBuffers...)
	w.outbound.access.Unlock()
	select {
	case w.outbound.wake <- struct{}{}:
	default:
	}
}

func (w *stackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	bind, err := w.bindAddress(destination)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		var tcpConn *tun.GoConn
		tcpConn, err = w.stack.DialTCP(ctx, bind, destination.AddrPort())
		if err != nil {
			return nil, err
		}
		tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 15 * time.Second})
		return tcpConn, nil
	case N.NetworkUDP:
		var udpConn *tun.GoUDPConn
		udpConn, err = w.stack.DialUDP(netip.AddrPortFrom(bind, 0), destination.AddrPort())
		if err != nil {
			return nil, err
		}
		return udpConn, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (w *stackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind, err := w.bindAddress(destination)
	if err != nil {
		return nil, err
	}
	udpConn, err := w.stack.ListenUDP(netip.AddrPortFrom(bind, 0))
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}

func (w *stackDevice) bindAddress(destination M.Socksaddr) (netip.Addr, error) {
	if destination.IsIPv4() {
		if !w.inet4Address.IsValid() {
			return netip.Addr{}, E.New("missing IPv4 local address")
		}
		return w.inet4Address, nil
	}
	if !w.inet6Address.IsValid() {
		return netip.Addr{}, E.New("missing IPv6 local address")
	}
	return w.inet6Address, nil
}

func (w *stackDevice) Inet4Address() netip.Addr {
	return w.inet4Address
}

func (w *stackDevice) Inet6Address() netip.Addr {
	return w.inet6Address
}

func (w *stackDevice) SetDevice(device *device.Device) {
}

func (w *stackDevice) Start() error {
	err := w.stack.Start()
	if err != nil {
		return err
	}
	w.events <- wgTun.EventUp
	return nil
}

func (w *stackDevice) File() *os.File {
	return nil
}

func (w *stackDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	for {
		w.outbound.access.Lock()
		count := 0
		for count < len(bufs) && len(w.outbound.pending) > 0 {
			packetBuffer := w.outbound.pending[0]
			w.outbound.pending = w.outbound.pending[1:]
			packet := packetBuffer.Bytes()
			target := bufs[count][offset:]
			if len(packet) > len(target) {
				packetBuffer.Release()
				continue
			}
			sizes[count] = copy(target, packet)
			packetBuffer.Release()
			count++
		}
		w.outbound.access.Unlock()
		if count > 0 {
			return count, nil
		}
		if w.closed.Load() {
			return 0, os.ErrClosed
		}
		select {
		case <-w.outbound.wake:
		case <-w.closeSignal:
		}
	}
}

func (w *stackDevice) Write(bufs [][]byte, offset int) (int, error) {
	packets := make([][]byte, 0, len(bufs))
	for _, packet := range bufs {
		packets = append(packets, packet[offset:])
	}
	return w.memoryTun.WritePackets(packets)
}

func (w *stackDevice) Flush() error {
	return nil
}

func (w *stackDevice) MTU() (int, error) {
	return int(w.mtu), nil
}

func (w *stackDevice) Name() (string, error) {
	return "sing-box", nil
}

func (w *stackDevice) Events() <-chan wgTun.Event {
	return w.events
}

func (w *stackDevice) Close() error {
	var err error
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		close(w.events)
		close(w.closeSignal)
		w.outbound.access.Lock()
		buf.ReleaseMulti(w.outbound.pending)
		w.outbound.pending = nil
		w.outbound.access.Unlock()
		err = E.Errors(w.stack.Close(), w.memoryTun.Close())
	})
	return err
}

func (w *stackDevice) BatchSize() int {
	return conn.IdealBatchSize
}
