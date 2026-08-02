package amneziawg

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type EndpointOptions struct {
	Context      context.Context
	Logger       logger.ContextLogger
	System       bool
	Handler      tun.Handler
	UDPTimeout   time.Duration
	Dialer       N.Dialer
	CreateDialer func(interfaceName string) N.Dialer
	Name         string
	MTU          uint32
	Address      []netip.Prefix
	PrivateKey   string
	ListenPort   uint16
	ResolvePeer  func(domain string) (netip.Addr, error)
	Peers        []PeerOptions

	// AmneziaWG obfuscation parameters. Empty/zero values are omitted from the
	// device IPC configuration, in which case the device behaves like plain
	// WireGuard.
	JunkPacketCount            int32  // jc
	JunkPacketMinSize          int32  // jmin
	JunkPacketMaxSize          int32  // jmax
	InitPacketJunkSize         int32  // s1
	ResponsePacketJunkSize     int32  // s2
	CookieReplyPacketJunkSize  int32  // s3
	TransportPacketJunkSize    int32  // s4
	InitPacketMagicHeader      string // h1
	ResponsePacketMagicHeader  string // h2
	UnderloadPacketMagicHeader string // h3
	TransportPacketMagicHeader string // h4
	SpecialJunk1               string // i1
	SpecialJunk2               string // i2
	SpecialJunk3               string // i3
	SpecialJunk4               string // i4
	SpecialJunk5               string // i5
}

type PeerOptions struct {
	Endpoint                    M.Socksaddr
	PublicKey                   string
	PreSharedKey                string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval uint16
	Reserved                    []uint8
}
