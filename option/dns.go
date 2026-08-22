package option

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type RawDNSOptions struct {
	Servers        []DNSServerOptions `json:"servers,omitempty"`
	Rules          []DNSRule          `json:"rules,omitempty"`
	Final          string             `json:"final,omitempty" reference:"dns_server"`
	ReverseMapping bool               `json:"reverse_mapping,omitempty"`
	DNSClientOptions
}

type DNSOptions struct {
	RawDNSOptions
}

const (
	legacyDNSFakeIPRemovedMessage = "legacy DNS fakeip options are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats"
	legacyDNSServerRemovedMessage = "legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats"
)

type removedLegacyDNSOptions struct {
	FakeIP *LegacyDNSFakeIPOptions `json:"fakeip,omitempty"`
}

type LegacyDNSFakeIPOptions struct {
	Enabled    bool              `json:"enabled,omitempty"`
	Inet4Range *badoption.Prefix `json:"inet4_range,omitempty"`
	Inet6Range *badoption.Prefix `json:"inet6_range,omitempty"`
}

func (o *DNSOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	var legacyOptions removedLegacyDNSOptions
	err := json.UnmarshalContext(ctx, content, &legacyOptions)
	if err != nil {
		return err
	}
	if err = badjson.UnmarshallExcludedContext(ctx, content, legacyOptions, &o.RawDNSOptions); err != nil {
		return err
	}

	// sing-box 1.14 moved the old top-level dns.fakeip ranges into a
	// type="fakeip" DNS server. Keep accepting pre-1.14 configurations and
	// attach their ranges to the upgraded legacy address="fakeip" server.
	if legacyOptions.FakeIP != nil && legacyOptions.FakeIP.Enabled {
		foundFakeIPServer := false
		for i := range o.Servers {
			if o.Servers[i].Type != C.DNSTypeFakeIP {
				continue
			}
			foundFakeIPServer = true
			fakeIPOptions, loaded := o.Servers[i].Options.(*FakeIPDNSServerOptions)
			if !loaded {
				return E.New("invalid fakeip DNS server options for ", o.Servers[i].Tag)
			}
			if fakeIPOptions.Inet4Range == nil {
				fakeIPOptions.Inet4Range = legacyOptions.FakeIP.Inet4Range
			}
			if fakeIPOptions.Inet6Range == nil {
				fakeIPOptions.Inet6Range = legacyOptions.FakeIP.Inet6Range
			}
		}
		if !foundFakeIPServer {
			o.Servers = append(o.Servers, DNSServerOptions{
				Type: C.DNSTypeFakeIP,
				Tag:  "fakeip",
				Options: &FakeIPDNSServerOptions{
					Inet4Range: legacyOptions.FakeIP.Inet4Range,
					Inet6Range: legacyOptions.FakeIP.Inet6Range,
				},
			})
		}
	}

	// sing-box 1.14 removed the synthetic rcode:// DNS transport. Older
	// NekoBox databases still contain servers such as
	// {"address":"rcode://name_error"} and rules routing to their tags.
	// DNSServerOptions keeps those entries as an internal marker while parsing;
	// remove the marker servers here and express the same behavior using the
	// 1.14 DNS rule action. This must happen before box.New validates the
	// transport registry, otherwise startup fails with "unknown transport type:
	// legacy_rcode" and the VPN service immediately tears down.
	rcodeMap := make(map[string]int)
	servers := make([]DNSServerOptions, 0, len(o.Servers))
	for _, server := range o.Servers {
		if server.Type == C.DNSTypeLegacyRcode {
			rcode, ok := server.Options.(int)
			if !ok {
				return E.New("invalid legacy rcode options for server ", server.Tag)
			}
			rcodeMap[server.Tag] = rcode
			continue
		}
		servers = append(servers, server)
	}
	o.Servers = servers
	for i := range o.Rules {
		rewriteDNSRcode(rcodeMap, &o.Rules[i])
	}
	return nil
}

func rewriteDNSRcode(rcodeMap map[string]int, rule *DNSRule) {
	switch rule.Type {
	case C.RuleTypeDefault:
		rewriteDNSRcodeAction(rcodeMap, &rule.DefaultOptions.DNSRuleAction)
	case C.RuleTypeLogical:
		rewriteDNSRcodeAction(rcodeMap, &rule.LogicalOptions.DNSRuleAction)
	}
}

func rewriteDNSRcodeAction(rcodeMap map[string]int, ruleAction *DNSRuleAction) {
	if ruleAction.Action != C.RuleActionTypeRoute {
		return
	}
	rcode, loaded := rcodeMap[ruleAction.RouteOptions.Server]
	if !loaded {
		return
	}
	ruleAction.Action = C.RuleActionTypePredefined
	ruleAction.PredefinedOptions.Rcode = common.Ptr(DNSRCode(rcode))
}

func (o DNSOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("DNS", func() (*schema.Node, error) {
		node := schema.StrictObject()
		err := builder.FlattenStruct(node, reflect.TypeFor[RawDNSOptions]())
		if err != nil {
			return nil, err
		}
		return node, nil
	})
}

type DNSClientOptions struct {
	Strategy         DomainStrategy        `json:"strategy,omitempty"`
	Timeout          badoption.Duration    `json:"timeout,omitempty"`
	DisableCache     bool                  `json:"disable_cache,omitempty"`
	DisableExpire    bool                  `json:"disable_expire,omitempty"`
	IndependentCache bool                  `json:"independent_cache,omitempty" schema:"omit"`
	CacheCapacity    uint32                `json:"cache_capacity,omitempty"`
	Optimistic       *OptimisticDNSOptions `json:"optimistic,omitempty"`
	ClientSubnet     *badoption.Prefixable `json:"client_subnet,omitempty"`
}

type _OptimisticDNSOptions struct {
	Enabled bool               `json:"enabled,omitempty"`
	Timeout badoption.Duration `json:"timeout,omitempty"`
}

type OptimisticDNSOptions _OptimisticDNSOptions

func (o OptimisticDNSOptions) MarshalJSON() ([]byte, error) {
	if o.Timeout == 0 {
		return json.Marshal(o.Enabled)
	}
	return json.Marshal((_OptimisticDNSOptions)(o))
}

func (o *OptimisticDNSOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, &o.Enabled)
	if err == nil {
		return nil
	}
	return json.UnmarshalDisallowUnknownFields(bytes, (*_OptimisticDNSOptions)(o))
}

func (o OptimisticDNSOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	objectForm := schema.StrictObject()
	err := builder.FlattenStruct(objectForm, reflect.TypeFor[OptimisticDNSOptions]())
	if err != nil {
		return nil, err
	}
	return schema.AnyOf(schema.BooleanNode(), objectForm), nil
}

type DNSTransportOptionsRegistry interface {
	OptionTypes() []string
	CreateOptions(transportType string) (any, bool)
}
type _DNSServerOptions struct {
	Type string `json:"type,omitempty"`
	Tag  string `json:"tag,omitempty"`
	// Legacy address format (sing-box < 1.12), auto-upgraded below.
	Address string `json:"address,omitempty"`
	Options any    `json:"-"`
}

type DNSServerOptions _DNSServerOptions

func (o *DNSServerOptions) MarshalJSONContext(ctx context.Context) ([]byte, error) {
	return badjson.MarshallObjectsContext(ctx, (*_DNSServerOptions)(o), o.Options)
}

func (o *DNSServerOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_DNSServerOptions)(o))
	if err != nil {
		return err
	}
	if (o.Type == "" || o.Type == C.DNSTypeLegacy) && o.Address != "" {
		// Legacy DNS server format (sing-box < 1.12): auto-upgrade to the new
		// "type" format so old configs (e.g. NekoBox-generated) keep working.
		serverURL, _ := url.Parse(o.Address)
		var serverType string
		if serverURL != nil && serverURL.Scheme != "" && serverURL.Host != "" {
			serverType = serverURL.Scheme
		} else {
			switch o.Address {
			case "local", "fakeip":
				serverType = o.Address
			default:
				serverType = C.DNSTypeUDP
			}
		}
		if serverType == "rcode" {
			// Legacy rcode server (sing-box < 1.14). We keep it as an internal
			// marker type; DNSOptions rewrites rules referencing it into
			// "predefined" + rcode actions after parsing.
			if serverURL == nil {
				return E.New("invalid rcode server address")
			}
			var rcode int
			switch serverURL.Host {
			case "success":
				rcode = 0
			case "format_error":
				rcode = 1
			case "server_failure":
				rcode = 2
			case "name_error":
				rcode = 3
			case "not_implemented":
				rcode = 4
			case "refused":
				rcode = 5
			default:
				return E.New("unknown rcode: ", serverURL.Host)
			}
			o.Type = C.DNSTypeLegacyRcode
			o.Options = rcode
			return nil
		}
		o.Type = serverType
		// Rebuild content with type set and address removed, then unmarshal the
		// type-specific options normally.
		var raw map[string]any
		if err = json.UnmarshalContext(ctx, content, &raw); err != nil {
			return err
		}
		delete(raw, "address")
		raw["type"] = o.Type
		legacyAddress := o.Address
		o.Address = "" // cleared; only meaningful for legacy upgrade
		// Legacy "address_resolver"/"address_strategy" map onto the new
		// "domain_resolver" dial option (same as upstream 1.13 Upgrade).
		if resolver, _ := raw["address_resolver"].(string); resolver != "" {
			delete(raw, "address_resolver")
			dr := map[string]any{"server": resolver}
			if strategy, _ := raw["address_strategy"].(string); strategy != "" {
				delete(raw, "address_strategy")
				dr["strategy"] = strategy
			}
			raw["domain_resolver"] = dr
		} else {
			delete(raw, "address_strategy")
		}
		if serverType == C.DNSTypeFakeIP {
			// New fakeip server options only carry the ranges; a legacy
			// "strategy" on a fakeip server is not supported anymore.
			delete(raw, "strategy")
		} else {
			// Server-level DNS response strategy was removed in the new DNS
			// server format (only the top-level dns.strategy exists now).
			// Drop it during upgrade so legacy configs keep parsing.
			delete(raw, "strategy")
		}
		if serverType == C.DNSTypeUDP || serverType == C.DNSTypeTCP || serverType == C.DNSTypeTLS || serverType == C.DNSTypeQUIC || serverType == C.DNSTypeHTTPS || serverType == C.DNSTypeHTTP3 {
			// address "https://host[:port]/path" or "8.8.8.8[:53]"
			var host, port, path string
			if serverURL != nil && serverURL.Scheme != "" && serverURL.Host != "" {
				host = serverURL.Hostname()
				port = serverURL.Port()
				path = serverURL.Path
			} else {
				addr := M.ParseSocksaddr(legacyAddress)
				host = addr.AddrString()
				if addr.Port != 0 {
					port = fmt.Sprint(addr.Port)
				}
			}
			if host != "" {
				raw["server"] = host
			}
			if port != "" {
				p, err := strconv.ParseUint(port, 10, 16)
				if err != nil {
					return E.Cause(err, "invalid server port")
				}
				raw["server_port"] = p
			}
			if path != "" && path != "/dns-query" {
				raw["path"] = path
			}
		}
		newContent, err := json.MarshalContext(ctx, raw)
		if err != nil {
			return err
		}
		content = newContent
	}
	registry := service.FromContext[DNSTransportOptionsRegistry](ctx)
	if registry == nil {
		return E.New("missing DNS transport options registry in context")
	}
	var options any
	switch o.Type {
	case "", C.DNSTypeLegacy:
		return E.New(legacyDNSServerRemovedMessage)
	default:
		var loaded bool
		options, loaded = registry.CreateOptions(o.Type)
		if !loaded {
			return E.New("unknown transport type: ", o.Type)
		}
	}
	err = badjson.UnmarshallExcludedContext(ctx, content, (*_DNSServerOptions)(o), options)
	if err != nil {
		return err
	}
	o.Options = options
	return nil
}

func (o DNSServerOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("DNSServer", func() (*schema.Node, error) {
		registry := service.FromContext[DNSTransportOptionsRegistry](builder.Context())
		if registry == nil {
			return nil, E.New("missing DNS transport options registry in context")
		}
		return registryUnion(builder, registry, nil, true)
	})
}

type DNSServerAddressOptions struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port,omitempty"`
}

func (o DNSServerAddressOptions) Build() M.Socksaddr {
	return M.ParseSocksaddrHostPort(o.Server, o.ServerPort)
}

func (o DNSServerAddressOptions) ServerIsDomain() bool {
	return o.Build().IsDomain()
}

func (o *DNSServerAddressOptions) TakeServerOptions() ServerOptions {
	return ServerOptions(*o)
}

func (o *DNSServerAddressOptions) ReplaceServerOptions(options ServerOptions) {
	*o = DNSServerAddressOptions(options)
}

type HostsDNSServerOptions struct {
	Path       badoption.Listable[string]                                `json:"path,omitempty"`
	Predefined *badjson.TypedMap[string, badoption.Listable[netip.Addr]] `json:"predefined,omitempty"`
}

type RawLocalDNSServerOptions struct {
	DialerOptions
}

type LocalDNSServerOptions struct {
	RawLocalDNSServerOptions
	PreferGo       bool                       `json:"prefer_go,omitempty"`
	NeighborDomain badoption.Listable[string] `json:"neighbor_domain,omitempty"`
}

type RemoteDNSServerOptions struct {
	RawLocalDNSServerOptions
	DNSServerAddressOptions
}

type RemoteTLSDNSServerOptions struct {
	RemoteDNSServerOptions
	OutboundTLSOptionsContainer
}

type RemoteHTTPSDNSServerOptions struct {
	RemoteTLSDNSServerOptions
	Path    string               `json:"path,omitempty"`
	Method  string               `json:"method,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
}

type FakeIPDNSServerOptions struct {
	Inet4Range *badoption.Prefix `json:"inet4_range,omitempty" examples:"198.18.0.0/15"`
	Inet6Range *badoption.Prefix `json:"inet6_range,omitempty" examples:"fc00::/18"`
}

type DHCPDNSServerOptions struct {
	LocalDNSServerOptions
	Interface string `json:"interface,omitempty"`
}

type MDNSDNSServerOptions struct {
	LocalDNSServerOptions
	Interface badoption.Listable[string] `json:"interface,omitempty"`
}
