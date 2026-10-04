//go:build with_tailscale

package tailscale

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tsconst"
)

// The callback runs inline and must return promptly. Endpoint Close cancels the
// request but does not wait for a potentially blocking foreign callback.
func (t *Endpoint) StartTailscalePing(ctx context.Context, peerIP string, fn func(*adapter.TailscalePingResult)) error {
	ip, err := netip.ParseAddr(peerIP)
	if err != nil {
		return err
	}
	ctx, cancel, _, err := t.managementContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	localClient := t.managementClient
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Expired disco transactions do not complete the local API callback.
		// Bound each attempt so a lost reply cannot stall subsequent samples.
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, tsconst.DefaultPingTimeout)
		result, pingErr := localClient.Ping(attemptCtx, ip, tailcfg.PingDisco)
		cancelAttempt()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if pingErr != nil {
			fn(&adapter.TailscalePingResult{
				Error: pingErr.Error(),
			})
		} else {
			fn(convertPingResult(result))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func convertPingResult(result *ipnstate.PingResult) *adapter.TailscalePingResult {
	return &adapter.TailscalePingResult{
		LatencyMs:      result.LatencySeconds * 1000,
		IsDirect:       result.Endpoint != "",
		Endpoint:       result.Endpoint,
		PeerRelay:      result.PeerRelay,
		DERPRegionID:   int32(result.DERPRegionID),
		DERPRegionCode: result.DERPRegionCode,
		Error:          result.Err,
	}
}
