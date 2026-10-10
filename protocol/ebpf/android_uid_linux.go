//go:build with_ebpf && !android

package ebpf

import (
	E "github.com/sagernet/sing/common/exceptions"

	tun "github.com/sagernet/sing-tun"
)

func androidPackageManager() (tun.PackageManager, error) {
	return nil, E.New("Android package policy is not supported on Linux")
}
