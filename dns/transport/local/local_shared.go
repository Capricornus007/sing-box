package local

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
<<<<<<< HEAD
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
=======
	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
	E "github.com/sagernet/sing/common/exceptions"
>>>>>>> sagerNet/testing

	mDNS "github.com/miekg/dns"
)

type localServerSet struct {
<<<<<<< HEAD
	config     *dnsConfig
=======
	config     *systemconfig.Config
>>>>>>> sagerNet/testing
	transports []adapter.DNSTransport
}

func (s *localServerSet) Close() {
	for _, serverTransport := range s.transports {
		serverTransport.Close()
	}
}

<<<<<<< HEAD
func (t *Transport) serverSetFor(systemConfig *dnsConfig) (*localServerSet, error) {
=======
func (t *Transport) serverSetFor(systemConfig *systemconfig.Config) (*localServerSet, error) {
>>>>>>> sagerNet/testing
	serverSet := t.serverSet.Load()
	if serverSet != nil && serverSet.config == systemConfig {
		return serverSet, nil
	}
	t.serverSetAccess.Lock()
	defer t.serverSetAccess.Unlock()
	serverSet = t.serverSet.Load()
	if serverSet != nil && serverSet.config == systemConfig {
		return serverSet, nil
	}
<<<<<<< HEAD
	transports := make([]adapter.DNSTransport, 0, len(systemConfig.servers))
	for _, server := range systemConfig.servers {
		serverAddr := M.ParseSocksaddr(server)
		if serverAddr.Port == 0 {
			serverAddr.Port = 53
		}
		var serverTransport adapter.DNSTransport
		if systemConfig.useTCP {
=======
	transports := make([]adapter.DNSTransport, 0, len(systemConfig.Servers))
	for _, serverAddr := range systemConfig.Servers {
		var serverTransport adapter.DNSTransport
		if systemConfig.UseTCP {
>>>>>>> sagerNet/testing
			serverTransport = transport.NewTCPRaw(dns.NewTransportAdapter(C.DNSTypeTCP, "", nil), t.dialer, serverAddr)
		} else {
			serverTransport = transport.NewUDPRaw(t.logger, dns.NewTransportAdapter(C.DNSTypeUDP, "", nil), t.dialer, serverAddr)
		}
		err := serverTransport.Start(adapter.StartStateStart)
		if err != nil {
			for _, startedTransport := range transports {
				startedTransport.Close()
			}
			return nil, E.Cause(err, "initialize transport for ", serverAddr)
		}
		transports = append(transports, serverTransport)
	}
	newServerSet := &localServerSet{
		config:     systemConfig,
		transports: transports,
	}
	oldServerSet := t.serverSet.Swap(newServerSet)
	if oldServerSet != nil {
		oldServerSet.Close()
	}
	return newServerSet, nil
}

func (t *Transport) exchangeAsync(ctx context.Context, message *mDNS.Msg, domain string, callback func(response *mDNS.Msg, err error)) {
<<<<<<< HEAD
	systemConfig := getSystemDNSConfig(t.ctx)
=======
	systemConfig := t.configSource.Configuration()
>>>>>>> sagerNet/testing
	serverSet, err := t.serverSetFor(systemConfig)
	if err != nil {
		callback(nil, err)
		return
	}
<<<<<<< HEAD
	names := systemConfig.nameList(domain)
=======
	names := systemConfig.NameList(domain)
>>>>>>> sagerNet/testing
	if len(names) == 0 {
		callback(nil, E.New("invalid domain: ", domain))
		return
	}
<<<<<<< HEAD
	nameExchangers := make([]transport.AsyncExchanger, 0, len(names))
	for _, fqdn := range names {
		nameExchangers = append(nameExchangers, newNameExchanger(systemConfig, serverSet, message, fqdn))
	}
	question := message.Question[0]
	if systemConfig.singleRequest || !(question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA) {
		transport.ExchangeSequential(ctx, nameExchangers, nil, callback)
	} else {
		transport.ExchangeRace(ctx, nameExchangers, callback)
	}
}

func newNameExchanger(systemConfig *dnsConfig, serverSet *localServerSet, message *mDNS.Msg, fqdn string) transport.AsyncExchanger {
	serverOffset := systemConfig.serverOffset()
	serverCount := uint32(len(serverSet.transports))
	attemptExchangers := make([]transport.AsyncExchanger, 0, systemConfig.attempts*int(serverCount))
	for i := 0; i < systemConfig.attempts; i++ {
		for j := range serverCount {
			serverTransport := serverSet.transports[(serverOffset+j)%serverCount]
			attemptExchangers = append(attemptExchangers, func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
				attemptCtx, cancel := context.WithTimeout(ctx, systemConfig.timeout)
				serverTransport.ExchangeAsync(attemptCtx, transport.NewFanOutRequest(message, fqdn, systemConfig.trustAD), func(response *mDNS.Msg, err error) {
					cancel()
					callback(response, err)
				})
			})
		}
	}
	return func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
		transport.ExchangeSequential(ctx, attemptExchangers, nil, func(response *mDNS.Msg, err error) {
			if err != nil {
				err = E.Cause(err, fqdn)
			}
			callback(response, err)
		})
	}
}
=======
	transport.ExchangeNames(ctx, names, message.Question[0], func(fqdn string) transport.AsyncExchanger {
		return newNameExchanger(systemConfig, serverSet, message, fqdn)
	}, callback)
}

func newNameExchanger(systemConfig *systemconfig.Config, serverSet *localServerSet, message *mDNS.Msg, fqdn string) transport.AsyncExchanger {
	serverOffset := systemConfig.ServerOffset()
	serverCount := uint32(len(serverSet.transports))
	attemptExchangers := make([]transport.AsyncExchanger, 0, systemConfig.Attempts*int(serverCount))
	for i := 0; i < systemConfig.Attempts; i++ {
		for j := range serverCount {
			serverTransport := serverSet.transports[(serverOffset+j)%serverCount]
			attemptExchangers = append(attemptExchangers, func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
				attemptCtx, cancel := context.WithTimeout(ctx, systemConfig.Timeout)
				serverTransport.ExchangeAsync(attemptCtx, transport.NewFanOutRequest(message, fqdn, systemConfig.TrustAD), func(response *mDNS.Msg, err error) {
					cancel()
					callback(response, err)
				})
			})
		}
	}
	return func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
		transport.ExchangeSequential(ctx, attemptExchangers, nil, func(response *mDNS.Msg, err error) {
			if err != nil {
				err = E.Cause(err, fqdn)
			}
			callback(response, err)
		})
	}
}
>>>>>>> sagerNet/testing
