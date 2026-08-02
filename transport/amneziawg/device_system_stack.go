//go:build with_gvisor

package amneziawg

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// System-interface mixed-stack mode is not supported for the AmneziaWG outbound:
// it relies on a sagernet/wireguard-go-specific Device.InputPacket extension that
// upstream amneziawg-go does not provide. The AmneziaWG outbound always runs in
// userspace gVisor netstack mode (System=false), so this path is unused.
func newSystemStackDevice(options DeviceOptions) (Device, error) {
	return nil, E.New("amneziawg: system-interface stack mode is not supported")
}
