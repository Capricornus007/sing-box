//go:build !(with_ebpf && (linux || android))

package ebpf

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	LC "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[LC.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

func NewInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options LC.EBPFInboundOptions,
) (adapter.Inbound, error) {
	return nil, E.New("eBPF inbound requires the with_ebpf build tag on linux/android")
}
