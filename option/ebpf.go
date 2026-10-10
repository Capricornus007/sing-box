package option

import (
	"net/netip"
	"strings"
)

type EBPFInboundOptions struct {
	Mode                 string     `json:"mode" yaml:"mode"`
	Network              []string   `json:"network" yaml:"network"`
	UDPTimeout           int64      `json:"udp_timeout" yaml:"udp_timeout"`
	DNSMode              string     `json:"dns_mode" yaml:"dns_mode"`
	BypassPrivateAddress *bool      `json:"bypass_private_address" yaml:"bypass_private_address"`
	BypassRuleSet        []string   `json:"bypass_rule_set" yaml:"bypass_rule_set"`
	Local                EBPFLocal  `json:"local" yaml:"local"`
	Shared               EBPFShared `json:"shared" yaml:"shared"`
}

type EBPFLocal struct {
	CgroupPath         string   `json:"cgroup_path" yaml:"cgroup_path"`
	IPv6Mode           string   `json:"ipv6_mode" yaml:"ipv6_mode"`
	IncludeUID         []uint32 `json:"include_uid" yaml:"include_uid"`
	IncludeUIDRange    []string `json:"include_uid_range" yaml:"include_uid_range"`
	ExcludeUID         []uint32 `json:"exclude_uid" yaml:"exclude_uid"`
	ExcludeUIDRange    []string `json:"exclude_uid_range" yaml:"exclude_uid_range"`
	IncludeAndroidUser []int    `json:"include_android_user" yaml:"include_android_user"`
	IncludePackage     []string `json:"include_package" yaml:"include_package"`
	ExcludePackage     []string `json:"exclude_package" yaml:"exclude_package"`
	StateCapacity      uint32   `json:"state_capacity" yaml:"state_capacity"`
}

type EBPFShared struct {
	Interface         []string           `json:"interface" yaml:"interface"`
	IPv6Mode          string             `json:"ipv6_mode" yaml:"ipv6_mode"`
	IncludeSourceCIDR []netip.Prefix     `json:"include_source_cidr" yaml:"include_source_cidr"`
	ExcludeSourceCIDR []netip.Prefix     `json:"exclude_source_cidr" yaml:"exclude_source_cidr"`
	IncludeMACAddress []string           `json:"include_mac_address" yaml:"include_mac_address"`
	ExcludeMACAddress []string           `json:"exclude_mac_address" yaml:"exclude_mac_address"`
	StateCapacity     uint32             `json:"state_capacity" yaml:"state_capacity"`
	Advanced          EBPFSharedAdvanced `json:"advanced" yaml:"advanced"`
}

type EBPFSharedAdvanced struct {
	TCPriority uint16 `json:"tc_priority" yaml:"tc_priority"`
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
