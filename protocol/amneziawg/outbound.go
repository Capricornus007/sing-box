package amneziawg

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/amneziawg"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AmneziaWGOutboundOptions](registry, C.TypeAmneziaWG, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	dnsRouter      adapter.DNSRouter
	logger         logger.ContextLogger
	localAddresses []netip.Prefix
	endpoint       *amneziawg.Endpoint
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AmneziaWGOutboundOptions) (adapter.Outbound, error) {
	outbound := &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(C.TypeAmneziaWG, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:            ctx,
		dnsRouter:      service.FromContext[adapter.DNSRouter](ctx),
		logger:         logger,
		localAddresses: options.LocalAddress,
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx,
		Options: options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain() || common.Any(options.Peers, func(it option.LegacyWireGuardPeer) bool {
			return it.ServerIsDomain()
		}),
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}
	peers := common.Map(options.Peers, func(it option.LegacyWireGuardPeer) amneziawg.PeerOptions {
		return amneziawg.PeerOptions{
			Endpoint:     it.ServerOptions.Build(),
			PublicKey:    it.PublicKey,
			PreSharedKey: it.PreSharedKey,
			AllowedIPs:   it.AllowedIPs,
			Reserved:     it.Reserved,
		}
	})
	if len(peers) == 0 {
		peers = []amneziawg.PeerOptions{{
			Endpoint:     options.ServerOptions.Build(),
			PublicKey:    options.PeerPublicKey,
			PreSharedKey: options.PreSharedKey,
			AllowedIPs:   []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)},
			Reserved:     options.Reserved,
		}}
	}
	wgEndpoint, err := amneziawg.NewEndpoint(amneziawg.EndpointOptions{
		Context: ctx,
		Logger:  logger,
		System:  options.SystemInterface,
		Dialer:  outboundDialer,
		CreateDialer: func(interfaceName string) N.Dialer {
			return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					BindInterface: interfaceName,
				},
			}))
		},
		Name:       options.InterfaceName,
		MTU:        options.MTU,
		Address:    options.LocalAddress,
		PrivateKey: options.PrivateKey,
		ResolvePeer: func(domain string) (netip.Addr, error) {
			endpointAddresses, lookupErr := outbound.dnsRouter.Lookup(ctx, domain, outboundDialer.(dialer.ResolveDialer).QueryOptions())
			if lookupErr != nil {
				return netip.Addr{}, lookupErr
			}
			return endpointAddresses[0], nil
		},
		Peers: peers,

		JunkPacketCount:            options.JunkPacketCount,
		JunkPacketMinSize:          options.JunkPacketMinSize,
		JunkPacketMaxSize:          options.JunkPacketMaxSize,
		InitPacketJunkSize:         options.InitPacketJunkSize,
		ResponsePacketJunkSize:     options.ResponsePacketJunkSize,
		CookieReplyPacketJunkSize:  options.CookieReplyPacketJunkSize,
		TransportPacketJunkSize:    options.TransportPacketJunkSize,
		InitPacketMagicHeader:      options.InitPacketMagicHeader,
		ResponsePacketMagicHeader:  options.ResponsePacketMagicHeader,
		UnderloadPacketMagicHeader: options.UnderloadPacketMagicHeader,
		TransportPacketMagicHeader: options.TransportPacketMagicHeader,
		SpecialJunk1:               options.SpecialJunk1,
		SpecialJunk2:               options.SpecialJunk2,
		SpecialJunk3:               options.SpecialJunk3,
		SpecialJunk4:               options.SpecialJunk4,
		SpecialJunk5:               options.SpecialJunk5,
	})
	if err != nil {
		return nil, err
	}
	outbound.endpoint = wgEndpoint
	return outbound, nil
}

func (o *Outbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateStart:
		return o.endpoint.Start(false)
	case adapter.StartStatePostStart:
		return o.endpoint.Start(true)
	}
	return nil
}

func (o *Outbound) Close() error {
	return o.endpoint.Close()
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, o.endpoint, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return o.endpoint.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, o.endpoint, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, err
	}
	return o.endpoint.ListenPacket(ctx, destination)
}
