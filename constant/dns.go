package constant

const (
	DefaultDNSTTL = 600
)

type DomainStrategy = uint8

const (
	DomainStrategyAsIS DomainStrategy = iota
	DomainStrategyPreferIPv4
	DomainStrategyPreferIPv6
	DomainStrategyIPv4Only
	DomainStrategyIPv6Only
)

const (
	DNSTypeLegacy = "legacy"
	// Internal compatibility type used while upgrading pre-1.14 rcode:// DNS servers.
	DNSTypeLegacyRcode = "legacy_rcode"
	DNSTypeUDP         = "udp"
	DNSTypeTCP         = "tcp"
	DNSTypeTLS         = "tls"
	DNSTypeHTTPS       = "https"
	DNSTypeQUIC        = "quic"
	DNSTypeHTTP3       = "h3"
	DNSTypeLocal       = "local"
	DNSTypeHosts       = "hosts"
	DNSTypeFakeIP      = "fakeip"
	DNSTypeDHCP        = "dhcp"
	DNSTypeMDNS        = "mdns"
	DNSTypeTailscale   = "tailscale"
	DNSTypeOpenConnect = "openconnect"
	DNSTypeOpenVPN     = "openvpn"
)

const (
	DNSProviderAliDNS     = "alidns"
	DNSProviderCloudflare = "cloudflare"
	DNSProviderACMEDNS    = "acmedns"
)
