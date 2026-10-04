//go:build with_gvisor

package tailscale

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tsconst"
)

func TestTailscalePingRetriesAfterLostDiscoReply(t *testing.T) {
	endpoint, _ := newExitTestEndpoint(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var attempts []context.Context
	endpoint.managementClient = &managementTestPinger{ping: func(attempt context.Context) (*ipnstate.PingResult, error) {
		attempts = append(attempts, attempt)
		deadline, ok := attempt.Deadline()
		if !ok || time.Until(deadline) > tsconst.DefaultPingTimeout {
			t.Fatal("disco attempt lacks the upstream per-attempt deadline")
		}
		if len(attempts) == 1 {
			// A lost disco request never invokes the native result callback,
			// even if later background discovery establishes a direct path.
			<-attempt.Done()
			return nil, attempt.Err()
		}
		return &ipnstate.PingResult{LatencySeconds: 0.007, Endpoint: "192.0.2.1:41641"}, nil
	}}
	var samples []*adapter.TailscalePingResult
	err := endpoint.StartTailscalePing(ctx, "100.64.0.2", func(result *adapter.TailscalePingResult) {
		if attempts[len(attempts)-1].Err() == nil {
			t.Fatal("completed attempt was not cancelled before its callback")
		}
		samples = append(samples, result)
		if len(samples) == 2 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || len(attempts) != 2 || len(samples) != 2 {
		t.Fatalf("lost attempt prevented a fresh sample: attempts=%d samples=%d error=%v", len(attempts), len(samples), err)
	}
	if samples[0].Error != context.DeadlineExceeded.Error() || samples[0].IsDirect || samples[0].LatencyMs != 0 {
		t.Fatalf("lost attempt appeared successful: %+v", samples[0])
	}
	if samples[1].Error != "" || !samples[1].IsDirect || samples[1].LatencyMs != 7 {
		t.Fatalf("fresh disco result was not preserved: %+v", samples[1])
	}
	for _, attempt := range attempts {
		if attempt.Err() == nil {
			t.Fatal("ping returned with a live attempt context")
		}
	}
}

func TestTailscalePingParentDeadlineStopsAttempt(t *testing.T) {
	endpoint, _ := newExitTestEndpoint(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var attemptContext context.Context
	attempts := 0
	endpoint.managementClient = &managementTestPinger{ping: func(attempt context.Context) (*ipnstate.PingResult, error) {
		attempts++
		attemptContext = attempt
		if got, ok := attempt.Deadline(); !ok || !got.Equal(deadline) {
			t.Fatal("attempt deadline extended the parent's shorter deadline")
		}
		<-attempt.Done()
		return nil, attempt.Err()
	}}
	started := time.Now()
	err := endpoint.StartTailscalePing(ctx, "100.64.0.2", func(*adapter.TailscalePingResult) {
		t.Error("sample emitted after parent deadline")
	})
	if !errors.Is(err, context.DeadlineExceeded) || attempts != 1 {
		t.Fatalf("parent deadline did not stop the attempt: attempts=%d error=%v", attempts, err)
	}
	if time.Since(started) >= time.Second || attemptContext.Err() == nil {
		t.Fatal("ping did not promptly release its attempt after parent deadline")
	}
}
