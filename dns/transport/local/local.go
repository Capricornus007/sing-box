package local

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
<<<<<<< HEAD
	"github.com/sagernet/sing-box/dns/transport/hosts"
=======
	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
>>>>>>> sagerNet/testing
	"github.com/sagernet/sing-box/dns/transport/mdns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.LocalDNSServerOptions](registry, C.DNSTypeLocal, NewTransport)
}

var (
	_ adapter.DNSTransport                    = (*Transport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*Transport)(nil)
<<<<<<< HEAD
=======
	_ adapter.DNSTransportWithEnvironment     = (*Transport)(nil)
>>>>>>> sagerNet/testing
)

type Transport struct {
	dns.TransportAdapter
<<<<<<< HEAD
	ctx             context.Context
	logger          logger.ContextLogger
	hosts           *hosts.File
	dialer          N.Dialer
	preferGo        bool
	fallback        bool
	resolved        ResolvedResolver
	mdnsTransport   adapter.DNSTransport
	dhcpTransport   dhcpTransport
	system          systemResolver
	serverSet       atomic.Pointer[localServerSet]
	serverSetAccess sync.Mutex

	neighborResolver adapter.NeighborResolver
	neighborSuffixes []string
}

type dhcpTransport interface {
	adapter.DNSTransport
	Fetch() []M.Socksaddr
=======
	ctx               context.Context
	logger            logger.ContextLogger
	preferredResolver *PreferredDomainResolver
	dialer            N.Dialer
	preferGo          bool
	resolved          ResolvedResolver
	mdnsTransport     adapter.DNSTransport
	configSource      *systemconfig.Source
	system            systemResolver
	serverSet         atomic.Pointer[localServerSet]
	serverSetAccess   sync.Mutex
>>>>>>> sagerNet/testing
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.LocalDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewLocalDialer(ctx, options)
	if err != nil {
		return nil, err
	}
<<<<<<< HEAD
	suffixes, err := buildNeighborMatchers(options.NeighborDomain)
=======
	preferredResolver, err := NewPreferredDomainResolver(ctx, logger, options)
>>>>>>> sagerNet/testing
	if err != nil {
		return nil, err
	}
	return &Transport{
<<<<<<< HEAD
		TransportAdapter: dns.NewTransportAdapterWithLocalOptions(C.DNSTypeLocal, tag, options),
		ctx:              ctx,
		logger:           logger,
		dialer:           transportDialer,
		preferGo:         options.PreferGo,
		neighborSuffixes: suffixes,
=======
		TransportAdapter:  dns.NewTransportAdapterWithLocalOptions(C.DNSTypeLocal, tag, options),
		ctx:               ctx,
		logger:            logger,
		preferredResolver: preferredResolver,
		dialer:            transportDialer,
		preferGo:          options.PreferGo,
		configSource:      systemconfig.NewSource(ctx),
>>>>>>> sagerNet/testing
	}, nil
}

func (t *Transport) Start(stage adapter.StartStage) error {
	t.preferredResolver.Start(stage)
	switch stage {
	case adapter.StartStateInitialize:
<<<<<<< HEAD
		defaultHosts, err := hosts.NewDefault()
		if err != nil {
			t.logger.Warn(err)
		} else {
			t.hosts = defaultHosts
		}
=======
>>>>>>> sagerNet/testing
		if !t.preferGo && isSystemdResolvedManaged() {
			resolvedResolver, err := NewResolvedResolver(t.ctx, t.logger)
			if err == nil {
				err = resolvedResolver.Start()
				if err == nil {
					t.resolved = resolvedResolver
				} else {
					t.logger.Warn(E.Cause(err, "initialize resolved resolver"))
				}
			}
		}
	case adapter.StartStateStart:
<<<<<<< HEAD
		if C.IsDarwin {
			inboundManager := service.FromContext[adapter.InboundManager](t.ctx)
			for _, inbound := range inboundManager.Inbounds() {
				if inbound.Type() == C.TypeTun {
					t.fallback = true
					break
				}
			}
			if t.fallback {
				t.dhcpTransport = newDHCPTransport(t.TransportAdapter, log.ContextWithOverrideLevel(t.ctx, log.LevelDebug), t.dialer, t.logger)
			}
		} else {
			t.mdnsTransport = mdns.NewRawTransport(t.TransportAdapter, t.ctx, t.logger)
		}
		router := service.FromContext[adapter.Router](t.ctx)
		if router != nil {
			t.neighborResolver = router.NeighborResolver()
		}
		fallthrough
	default:
		if t.dhcpTransport != nil {
			err := t.dhcpTransport.Start(stage)
			if err != nil {
				return err
			}
		}
=======
		if !C.IsDarwin {
			t.mdnsTransport = mdns.NewRawTransport(t.TransportAdapter, t.ctx, t.logger)
		}
		fallthrough
	default:
>>>>>>> sagerNet/testing
		if t.mdnsTransport != nil {
			err := t.mdnsTransport.Start(stage)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Transport) Close() error {
	serverSet := t.serverSet.Swap(nil)
	if serverSet != nil {
		serverSet.Close()
	}
	t.system.close()
<<<<<<< HEAD
	return common.Close(t.resolved, t.dhcpTransport, t.mdnsTransport)
=======
	return common.Close(t.resolved, t.mdnsTransport, t.configSource)
>>>>>>> sagerNet/testing
}

func (t *Transport) Reset() {
	serverSet := t.serverSet.Load()
	if serverSet != nil {
		for _, serverTransport := range serverSet.transports {
			serverTransport.Reset()
		}
	}
	t.system.reset()
<<<<<<< HEAD
	if t.resolved != nil {
		t.resolved.Reset()
	}
	if t.dhcpTransport != nil {
		t.dhcpTransport.Reset()
	}
=======
	t.configSource.Reset()
	if t.resolved != nil {
		t.resolved.Reset()
	}
>>>>>>> sagerNet/testing
	if t.mdnsTransport != nil {
		t.mdnsTransport.Reset()
	}
}

func (t *Transport) PreferredDomain(domain string) bool {
<<<<<<< HEAD
	if t.hosts != nil {
		if len(t.hosts.Lookup(dns.FqdnToDomain(domain))) > 0 {
			return true
		}
	}
	return t.hasNeighborHost(domain) || mdns.IsLocalDomain(domain)
=======
	return t.preferredResolver.PreferredDomain(domain)
}

func (t *Transport) Environment() []string {
	if t.resolved != nil {
		return t.resolved.Environment()
	}
	return t.configSource.Configuration().Signature()
>>>>>>> sagerNet/testing
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	done := make(chan struct{})
	var (
		response *mDNS.Msg
		err      error
	)
	t.ExchangeAsync(ctx, message, func(callbackResponse *mDNS.Msg, callbackErr error) {
		response = callbackResponse
		err = callbackErr
		close(done)
	})
	<-done
	return response, err
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	question := message.Question[0]
<<<<<<< HEAD
	if t.hosts != nil && (question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA) {
		addresses := t.hosts.Lookup(dns.FqdnToDomain(question.Name))
		if len(addresses) > 0 {
			callback(dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil)
=======
	response := t.preferredResolver.Lookup(message)
	if response != nil {
		callback(response, nil)
		return
	}
	if mdns.IsLocalDomain(question.Name) {
		if C.IsDarwin {
			t.systemExchangeAsync(ctx, message, callback)
>>>>>>> sagerNet/testing
			return
		}
		t.mdnsTransport.ExchangeAsync(ctx, message, callback)
		return
	}
	if t.resolved != nil {
		t.resolved.ExchangeAsync(ctx, message, callback)
		return
	}
<<<<<<< HEAD
	response := t.lookupNeighbor(message)
	if response != nil {
		callback(response, nil)
		return
	}
	if mdns.IsLocalDomain(question.Name) {
		if C.IsDarwin {
			t.systemExchangeAsync(ctx, message, callback)
			return
		}
		t.mdnsTransport.ExchangeAsync(ctx, message, callback)
		return
	}
	if t.resolved != nil {
		t.resolved.ExchangeAsync(ctx, message, callback)
		return
	}
	if t.dhcpTransport != nil {
		servers := t.dhcpTransport.Fetch()
		if len(servers) > 0 {
			t.dhcpTransport.ExchangeAsync(ctx, message, callback)
			return
		}
	}
	if t.fallback {
		t.systemExchangeAsync(ctx, message, callback)
		return
	}
=======
>>>>>>> sagerNet/testing
	t.exchangeAsync(ctx, message, question.Name, callback)
}
