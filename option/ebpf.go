package option

import (
	"net/netip"
	"strings"
)

type EBPFInboundOptions struct {
	Mode                 string     `json:"mode" yaml:"mode"`
	Network              []string   `json:"network" yaml:"network"`
	UDPTimeout           int64      `json:"udp-timeout" yaml:"udp-timeout"`
	DNSMode              string     `json:"dns-mode" yaml:"dns-mode"`
	BypassPrivateAddress *bool      `json:"bypass-private-address" yaml:"bypass-private-address"`
	BypassRuleSet        []string   `json:"bypass-rule-set" yaml:"bypass-rule-set"`
	Local                EBPFLocal  `json:"local" yaml:"local"`
	Shared               EBPFShared `json:"shared" yaml:"shared"`
}

type EBPFLocal struct {
	CgroupPath         string   `json:"cgroup-path" yaml:"cgroup-path"`
	IPv6Mode           string   `json:"ipv6-mode" yaml:"ipv6-mode"`
	IncludeUID         []uint32 `json:"include-uid" yaml:"include-uid"`
	IncludeUIDRange    []string `json:"include-uid-range" yaml:"include-uid-range"`
	ExcludeUID         []uint32 `json:"exclude-uid" yaml:"exclude-uid"`
	ExcludeUIDRange    []string `json:"exclude-uid-range" yaml:"exclude-uid-range"`
	IncludeAndroidUser []int    `json:"include-android-user" yaml:"include-android-user"`
	IncludePackage     []string `json:"include-package" yaml:"include-package"`
	ExcludePackage     []string `json:"exclude-package" yaml:"exclude-package"`
	StateCapacity      uint32   `json:"state-capacity" yaml:"state-capacity"`
}

type EBPFShared struct {
	Interface         []string           `json:"interface" yaml:"interface"`
	IPv6Mode          string             `json:"ipv6-mode" yaml:"ipv6-mode"`
	IncludeSourceCIDR []netip.Prefix     `json:"include-source-cidr" yaml:"include-source-cidr"`
	ExcludeSourceCIDR []netip.Prefix     `json:"exclude-source-cidr" yaml:"exclude-source-cidr"`
	IncludeMACAddress []string           `json:"include-mac-address" yaml:"include-mac-address"`
	ExcludeMACAddress []string           `json:"exclude-mac-address" yaml:"exclude-mac-address"`
	StateCapacity     uint32             `json:"state-capacity" yaml:"state-capacity"`
	Advanced          EBPFSharedAdvanced `json:"advanced" yaml:"advanced"`
}

type EBPFSharedAdvanced struct {
	TCPriority uint16 `json:"tc-priority" yaml:"tc-priority"`
}

func (c EBPFInboundOptions) String() string {
	builder := &strings.Builder{}
	builder.WriteString("mode=")
	builder.WriteString(c.Mode)
	builder.WriteString(", network=")
	builder.WriteString(strings.Join(c.Network, ","))
	builder.WriteString(", dns_mode=")
	builder.WriteString(c.DNSMode)
	return builder.String()
}
