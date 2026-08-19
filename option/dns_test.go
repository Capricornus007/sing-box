package option

import (
	"context"
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type stubDNSTransportOptionsRegistry struct{}

func (stubDNSTransportOptionsRegistry) OptionTypes() []string {
	return []string{C.DNSTypeUDP, C.DNSTypeFakeIP}
}

func (stubDNSTransportOptionsRegistry) CreateOptions(transportType string) (any, bool) {
	switch transportType {
	case C.DNSTypeUDP:
		return new(RemoteDNSServerOptions), true
	case C.DNSTypeFakeIP:
		return new(FakeIPDNSServerOptions), true
	default:
		return nil, false
	}
}

func TestDNSOptionsUpgradesLegacyFakeIPOptions(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	var options DNSOptions
	err := json.UnmarshalContext(ctx, []byte(`{
		"servers": [{"tag":"dns-fake", "address":"fakeip"}],
		"rules": [{"inbound":["tun-in"], "server":"dns-fake"}],
		"fakeip": {
			"enabled": true,
			"inet4_range": "198.18.0.0/15",
			"inet6_range": "fc00::/18"
		}
	}`), &options)
	require.NoError(t, err)
	require.Len(t, options.Servers, 1)
	require.Equal(t, C.DNSTypeFakeIP, options.Servers[0].Type)
	fakeIPOptions, loaded := options.Servers[0].Options.(*FakeIPDNSServerOptions)
	require.True(t, loaded)
	require.Equal(t, "198.18.0.0/15", fakeIPOptions.Inet4Range.Build(netip.Prefix{}).String())
	require.Equal(t, "fc00::/18", fakeIPOptions.Inet6Range.Build(netip.Prefix{}).String())
}

func TestDNSServerOptionsUpgradesLegacyFormats(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	testCases := []string{
		`{"address":"1.1.1.1"}`,
		`{"type":"legacy","address":"1.1.1.1"}`,
	}
	for _, content := range testCases {
		var options DNSServerOptions
		err := json.UnmarshalContext(ctx, []byte(content), &options)
		require.NoError(t, err)
		require.Equal(t, C.DNSTypeUDP, options.Type)
		remoteOptions, loaded := options.Options.(*RemoteDNSServerOptions)
		require.True(t, loaded)
		require.Equal(t, "1.1.1.1", remoteOptions.Server)
	}
}

func TestDNSOptionsUpgradesLegacyRcodeServer(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	var options DNSOptions
	err := json.UnmarshalContext(ctx, []byte(`{
		"servers": [{"tag":"rcode", "address":"rcode://name_error"}],
		"rules": [{"domain":["example.com"], "server":"rcode"}]
	}`), &options)
	require.NoError(t, err)
	require.Empty(t, options.Servers)
	require.Len(t, options.Rules, 1)
	action := options.Rules[0].DefaultOptions.DNSRuleAction
	require.Equal(t, C.RuleActionTypePredefined, action.Action)
	require.NotNil(t, action.PredefinedOptions.Rcode)
	require.Equal(t, DNSRCode(3), *action.PredefinedOptions.Rcode)
}
