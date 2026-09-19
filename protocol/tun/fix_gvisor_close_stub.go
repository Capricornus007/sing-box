//go:build !with_gvisor

package tun

import singtun "github.com/sagernet/sing-tun"

//nolint:unused // paired stub for forceCloseGVisorStack; the real implementation lives behind //go:build with_gvisor, and this stub keeps the symbol resolvable across the build matrix. Called by the Nekobox+ sing-box patch stream.
func forceCloseGVisorStack(stack singtun.Stack) {}
