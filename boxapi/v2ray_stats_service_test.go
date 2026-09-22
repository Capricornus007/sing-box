package boxapi

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type statsOutbound struct{ adapter.Outbound }

func (statsOutbound) Tag() string { return "edge" }

func TestRoutedFlowKeepsTrafficCounters(t *testing.T) {
	s := NewSbStatsService(option.V2RayStatsServiceOptions{Enabled: true, Inbounds: []string{"tun"}, Outbounds: []string{"edge"}, Users: []string{"reader"}})
	flow := s.RoutedFlow(context.Background(), adapter.InboundContext{Inbound: "tun", User: "reader"}, nil, statsOutbound{})
	if flow == nil {
		t.Fatal("missing flow tracker")
	}
	flow.CountForward(12)
	flow.CountReverse(34)
	for _, scope := range []string{"inbound>>>tun", "outbound>>>edge", "user>>>reader"} {
		for direction, expected := range map[string]int64{"uplink": 12, "downlink": 34} {
			key := scope + ">>>traffic>>>" + direction
			value, err := s.GetStats(context.Background(), key, true)
			if err != nil || value != expected {
				t.Fatalf("%s: %d, %v", key, value, err)
			}
			value, err = s.GetStats(context.Background(), key, false)
			if err != nil || value != 0 {
				t.Fatalf("reset %s: %d, %v", key, value, err)
			}
		}
	}
	untracked := NewSbStatsService(option.V2RayStatsServiceOptions{Enabled: true})
	if untracked.RoutedFlow(context.Background(), adapter.InboundContext{}, nil, statsOutbound{}) != nil {
		t.Fatal("unselected flow was tracked")
	}
}
