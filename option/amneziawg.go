package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type AmneziaWGOutboundOptions struct {
	DialerOptions
	SystemInterface bool                             `json:"system_interface,omitempty"`
	InterfaceName   string                           `json:"interface_name,omitempty"`
	LocalAddress    badoption.Listable[netip.Prefix] `json:"local_address"`
	PrivateKey      string                           `json:"private_key"`
	Peers           []LegacyWireGuardPeer            `json:"peers,omitempty"`
	ServerOptions
	PeerPublicKey string      `json:"peer_public_key"`
	PreSharedKey  string      `json:"pre_shared_key,omitempty"`
	Reserved      []uint8     `json:"reserved,omitempty"`
	MTU           uint32      `json:"mtu,omitempty"`
	Network       NetworkList `json:"network,omitempty"`

	// AmneziaWG obfuscation parameters.
	JunkPacketCount            int32  `json:"jc,omitempty"`
	JunkPacketMinSize          int32  `json:"jmin,omitempty"`
	JunkPacketMaxSize          int32  `json:"jmax,omitempty"`
	InitPacketJunkSize         int32  `json:"s1,omitempty"`
	ResponsePacketJunkSize     int32  `json:"s2,omitempty"`
	CookieReplyPacketJunkSize  int32  `json:"s3,omitempty"`
	TransportPacketJunkSize    int32  `json:"s4,omitempty"`
	InitPacketMagicHeader      string `json:"h1,omitempty"`
	ResponsePacketMagicHeader  string `json:"h2,omitempty"`
	UnderloadPacketMagicHeader string `json:"h3,omitempty"`
	TransportPacketMagicHeader string `json:"h4,omitempty"`
	SpecialJunk1               string `json:"i1,omitempty"`
	SpecialJunk2               string `json:"i2,omitempty"`
	SpecialJunk3               string `json:"i3,omitempty"`
	SpecialJunk4               string `json:"i4,omitempty"`
	SpecialJunk5               string `json:"i5,omitempty"`
}

// LegacyWireGuardOutboundOptions is the plain WireGuard outbound schema used by
// nekobox. Upstream 1.13 removed the wireguard outbound (endpoint-only); neko
// restores it on top of transport/amneziawg with all obfuscation params left at
// zero (identity), so the device behaves like plain WireGuard.
type LegacyWireGuardOutboundOptions struct {
	DialerOptions
	SystemInterface bool                             `json:"system_interface,omitempty"`
	InterfaceName   string                           `json:"interface_name,omitempty"`
	LocalAddress    badoption.Listable[netip.Prefix] `json:"local_address"`
	PrivateKey      string                           `json:"private_key"`
	Peers           []LegacyWireGuardPeer            `json:"peers,omitempty"`
	ServerOptions
	PeerPublicKey string      `json:"peer_public_key"`
	PreSharedKey  string      `json:"pre_shared_key,omitempty"`
	Reserved      []uint8     `json:"reserved,omitempty"`
	Workers       int         `json:"workers,omitempty"`
	MTU           uint32      `json:"mtu,omitempty"`
	Network       NetworkList `json:"network,omitempty"`
}

// LegacyWireGuardPeer is the AmneziaWG peer config. It mirrors the legacy
// WireGuard peer schema (Server/ServerPort via embedded ServerOptions) so
// existing AmneziaWG configs remain valid on the 1.13 base, where upstream
// renamed its own peer type to WireGuardPeer with a different shape.
type LegacyWireGuardPeer struct {
	ServerOptions
	PublicKey    string                           `json:"public_key,omitempty"`
	PreSharedKey string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs   badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	Reserved     []uint8                          `json:"reserved,omitempty"`
}
