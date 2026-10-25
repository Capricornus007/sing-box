package rule

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func newSniffAction(t *testing.T, config string) *RuleActionSniff {
	t.Helper()
	var options option.RuleAction
	require.NoError(t, json.Unmarshal([]byte(config), &options))
	require.Equal(t, C.RuleActionTypeSniff, options.Action)
	action, err := NewRuleAction(context.Background(), log.NewNOPFactory().NewLogger("router"), options)
	require.NoError(t, err)
	return action.(*RuleActionSniff)
}

func TestSniffActionOverridesDestinationWithSniffedDomain(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","sniffer":["tls"],"override_destination":true}`)
	require.True(t, action.OverrideDestination)
	require.Equal(t, "sniff(tls,override_destination)", action.String())

	address := M.ParseSocksaddrHostPort("192.0.2.7", 443)
	metadata := adapter.InboundContext{Domain: "example.com", Destination: address}
	action.ApplyDestination(&metadata)
	require.Equal(t, M.Socksaddr{Fqdn: "example.com", Port: 443}, metadata.Destination)
	// Packets still addressed to the dialed address are mapped to the name.
	require.Equal(t, address, metadata.RouteOriginalDestination)
}

func TestSniffActionOverrideDropsAddressesResolvedForTheOldDestination(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","override_destination":true}`)
	metadata := adapter.InboundContext{
		Domain:               "b.example",
		Destination:          M.Socksaddr{Fqdn: "a.example", Port: 443},
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.7")},
	}
	action.ApplyDestination(&metadata)
	require.Equal(t, M.Socksaddr{Fqdn: "b.example", Port: 443}, metadata.Destination)
	require.Empty(t, metadata.DestinationAddresses)
	require.Equal(t, M.Socksaddr{Fqdn: "a.example", Port: 443}, metadata.RouteOriginalDestination)

	// The same name again changes nothing, and keeps its resolved addresses.
	same := adapter.InboundContext{
		Domain:               "b.example",
		Destination:          M.Socksaddr{Fqdn: "b.example", Port: 443},
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.8")},
	}
	action.ApplyDestination(&same)
	require.Len(t, same.DestinationAddresses, 1)
	require.False(t, same.RouteOriginalDestination.IsValid())
}

func TestSniffActionKeepsDestinationWithoutOverride(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff"}`)
	require.False(t, action.OverrideDestination)
	require.Equal(t, "sniff", action.String())

	address := M.ParseSocksaddrHostPort("192.0.2.7", 443)
	metadata := adapter.InboundContext{Domain: "example.com", Destination: address}
	action.ApplyDestination(&metadata)
	require.Equal(t, address, metadata.Destination)
}

func TestSniffActionOverrideIgnoresNamesThatAreNotDomains(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","timeout":"1s","override_destination":true}`)
	require.Equal(t, "sniff(1s,override_destination)", action.String())
	address := M.ParseSocksaddrHostPort("192.0.2.7", 443)
	// No sniffed name, and an address in place of a name: the dialed address stays.
	for _, domain := range []string{"", "198.51.100.1"} {
		metadata := adapter.InboundContext{Domain: domain, Destination: address}
		action.ApplyDestination(&metadata)
		require.Equal(t, address, metadata.Destination, domain)
	}
}
