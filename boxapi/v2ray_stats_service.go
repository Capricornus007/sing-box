package boxapi

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*SbStatsService)(nil)

type SbStatsService struct {
	inbounds  map[string]bool
	outbounds map[string]bool
	users     map[string]bool
	access    sync.Mutex
	counters  map[string]*atomic.Int64
}

func NewSbStatsService(options option.V2RayStatsServiceOptions) *SbStatsService {
	if !options.Enabled {
		return nil
	}
	s := &SbStatsService{inbounds: make(map[string]bool), outbounds: make(map[string]bool), users: make(map[string]bool), counters: make(map[string]*atomic.Int64)}
	for _, tag := range options.Inbounds {
		s.inbounds[tag] = true
	}
	for _, tag := range options.Outbounds {
		s.outbounds[tag] = true
	}
	for _, tag := range options.Users {
		s.users[tag] = true
	}
	return s
}

func (s *SbStatsService) flowCounters(inbound, outbound, user string) ([]*atomic.Int64, []*atomic.Int64) {
	var up, down []*atomic.Int64
	s.access.Lock()
	defer s.access.Unlock()
	for _, scope := range []struct {
		prefix  string
		enabled bool
	}{
		{"inbound>>>" + inbound, inbound != "" && s.inbounds[inbound]},
		{"outbound>>>" + outbound, outbound != "" && s.outbounds[outbound]},
		{"user>>>" + user, user != "" && s.users[user]},
	} {
		if scope.enabled {
			up = append(up, s.loadOrCreateCounter(scope.prefix+">>>traffic>>>uplink"))
			down = append(down, s.loadOrCreateCounter(scope.prefix+">>>traffic>>>downlink"))
		}
	}
	return up, down
}

func (s *SbStatsService) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	return s.RoutedConnectionInternal(metadata.Inbound, matchOutbound.Tag(), metadata.User, conn, true)
}

func (s *SbStatsService) RoutedConnectionInternal(inbound, outbound, user string, conn net.Conn, directIn bool) net.Conn {
	up, down := s.flowCounters(inbound, outbound, user)
	if len(up) == 0 {
		return conn
	}
	if directIn {
		return bufio.NewInt64CounterConn(conn, up, down)
	}
	return bufio.NewInt64CounterConn(conn, down, up)
}

func (s *SbStatsService) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	up, down := s.flowCounters(metadata.Inbound, matchOutbound.Tag(), metadata.User)
	if len(up) == 0 {
		return conn
	}
	return bufio.NewInt64CounterPacketConn(conn, up, nil, down, nil)
}

func (s *SbStatsService) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	up, down := s.flowCounters(metadata.Inbound, matchOutbound.Tag(), metadata.User)
	if len(up) == 0 {
		return nil
	}
	return &statsFlowTracker{up: up, down: down}
}

type statsFlowTracker struct{ up, down []*atomic.Int64 }

func (*statsFlowTracker) AttachFlow(tun.FlowHandle)     {}
func (*statsFlowTracker) FlowEstablished()              {}
func (*statsFlowTracker) CloseFlow(tun.FlowCloseReason) {}
func (t *statsFlowTracker) CountForward(n int) {
	for _, counter := range t.up {
		counter.Add(int64(n))
	}
}
func (t *statsFlowTracker) CountReverse(n int) {
	for _, counter := range t.down {
		counter.Add(int64(n))
	}
}

func (s *SbStatsService) GetStats(ctx context.Context, name string, reset bool) (int64, error) {
	s.access.Lock()
	counter, loaded := s.counters[name]
	s.access.Unlock()
	if !loaded {
		return 0, E.New(name, " not found.")
	}
	if reset {
		return counter.Swap(0), nil
	}
	return counter.Load(), nil
}

func (s *SbStatsService) loadOrCreateCounter(name string) *atomic.Int64 {
	counter := s.counters[name]
	if counter == nil {
		counter = &atomic.Int64{}
		s.counters[name] = counter
	}
	return counter
}
