package option

// V2RayKCPOptions configures the mKCP transport.
//
// Xray-core v26.2 and later send raw KCP segments and move the old packet obfuscation into
// finalmask. Seed selects AES-128-GCM and HeaderType a packet header, as in Xray's mkcp-legacy
// masks. Legacy adds the checksum that older servers expect when no seed is set.
type V2RayKCPOptions struct {
	MTU              uint32 `json:"mtu,omitempty"`
	TTI              uint32 `json:"tti,omitempty"`
	UplinkCapacity   uint32 `json:"uplink_capacity,omitempty"`
	DownlinkCapacity uint32 `json:"downlink_capacity,omitempty"`
	Congestion       bool   `json:"congestion,omitempty"`
	ReadBufferSize   uint32 `json:"read_buffer_size,omitempty"`
	WriteBufferSize  uint32 `json:"write_buffer_size,omitempty"`
	HeaderType       string `json:"header_type,omitempty"`
	Seed             string `json:"seed,omitempty"`
	Legacy           bool   `json:"legacy,omitempty"`
	CwndMultiplier   uint32 `json:"cwnd_multiplier,omitempty"`
	MaxSendingWindow uint32 `json:"max_sending_window,omitempty"`
}
