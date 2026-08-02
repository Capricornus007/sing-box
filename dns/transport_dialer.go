package dns

import (
	"context"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func NewLocalDialer(ctx context.Context, options option.LocalDNSServerOptions) (N.Dialer, error) {
	return dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		DirectResolver: true,
		// DNS servers frequently detour to a plain "direct" outbound (e.g.
		// NekoBox's dns-local/dns-direct). In 1.14 the empty-direct detour
		// check rejects that; keep the pre-1.13 legacy DNS behavior.
		DisableEmptyDirectCheck: true,
	})
}

func NewRemoteDialer(ctx context.Context, options option.RemoteDNSServerOptions) (N.Dialer, error) {
	return dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
		DirectResolver: true,
		// See NewLocalDialer: DNS servers detouring to an empty direct
		// outbound is a legitimate, long-standing configuration.
		DisableEmptyDirectCheck: true,
	})
}
