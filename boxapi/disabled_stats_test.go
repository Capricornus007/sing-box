package boxapi

import (
	"github.com/sagernet/sing-box/option"
	"testing"
)

func TestDisabledStatsHaveNoTracker(t *testing.T) {
	server := NewSbV2rayServer(option.V2RayStatsServiceOptions{})
	if server.StatsService() != nil {
		t.Fatal("disabled stats returned a typed nil tracker")
	}
	if server.QueryStats("missing") != 0 {
		t.Fatal("disabled stats returned traffic")
	}
}
