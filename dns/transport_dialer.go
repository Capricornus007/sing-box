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
		// DNS server detours intentionally use an empty direct outbound to
		// bypass the proxy. This is the documented equivalent of the legacy
		// DNS server default and must not be rejected by the generic detour
		// safety check.
		DisableEmptyDirectCheck: true,
	})
}

func NewRemoteDialer(ctx context.Context, options option.RemoteDNSServerOptions) (N.Dialer, error) {
	return dialer.NewWithOptions(dialer.Options{
		Context:                 ctx,
		Options:                 options.DialerOptions,
		RemoteIsDomain:          options.ServerIsDomain(),
		DirectResolver:          true,
		DisableEmptyDirectCheck: true,
	})
}
