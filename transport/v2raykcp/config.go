package v2raykcp

import (
	"crypto/cipher"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// Config stores the configurations for KCP transport
type Config struct {
	MTU              uint32
	TTI              uint32
	UplinkCapacity   uint32
	DownlinkCapacity uint32
	Congestion       bool
	ReadBufferSize   uint32
	WriteBufferSize  uint32
	HeaderType       string
	Seed             string
	Legacy           bool
	CwndMultiplier   uint32
	MaxSendingWindow uint32
}

// NewConfig applies Xray's defaults and limits to the options.
func NewConfig(options option.V2RayKCPOptions) (*Config, error) {
	config := &Config{
		MTU:              options.MTU,
		TTI:              options.TTI,
		UplinkCapacity:   options.UplinkCapacity,
		DownlinkCapacity: options.DownlinkCapacity,
		Congestion:       options.Congestion,
		ReadBufferSize:   options.ReadBufferSize,
		WriteBufferSize:  options.WriteBufferSize,
		HeaderType:       options.HeaderType,
		Seed:             options.Seed,
		Legacy:           options.Legacy,
		CwndMultiplier:   options.CwndMultiplier,
		MaxSendingWindow: options.MaxSendingWindow,
	}
	if config.MTU == 0 {
		config.MTU = 1350
	}
	if config.TTI == 0 {
		config.TTI = 50
	}
	if config.UplinkCapacity == 0 {
		config.UplinkCapacity = 5
	}
	if config.DownlinkCapacity == 0 {
		config.DownlinkCapacity = 20
	}
	if config.CwndMultiplier == 0 {
		config.CwndMultiplier = 1
	}
	// The ranges Xray accepts.
	if config.MTU < 576 || config.MTU > 1460 {
		return nil, E.New("mKCP MTU must be between 576 and 1460")
	}
	if config.TTI < 10 || config.TTI > 100 {
		return nil, E.New("mKCP TTI must be between 10 and 100")
	}
	if _, err := NewPacketHeader(config.GetHeaderType()); err != nil {
		return nil, err
	}
	if config.GetSendingBufferSize() == 0 {
		return nil, E.New("mKCP sending window must be at least the MTU")
	}
	return config, nil
}

// GetMTUValue returns the value of MTU settings.
func (c *Config) GetMTUValue() uint32 {
	return c.MTU
}

// GetTTIValue returns the value of TTI settings.
func (c *Config) GetTTIValue() uint32 {
	return c.TTI
}

// GetWriteBufferSize returns the size of WriterBuffer in bytes.
func (c *Config) GetWriteBufferSize() uint32 {
	if c.WriteBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.WriteBufferSize * 1024 * 1024
}

// GetReadBufferSize returns the size of ReadBuffer in bytes.
func (c *Config) GetReadBufferSize() uint32 {
	if c.ReadBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.ReadBufferSize * 1024 * 1024
}

// GetSecurity returns the packet protection: AES-128-GCM with a seed, the legacy checksum, or
// none. Xray-core v26.2 and later send raw segments unless finalmask adds one of the first two.
func (c *Config) GetSecurity() (cipher.AEAD, error) {
	if c.Seed != "" {
		return NewAEADAESGCMBasedOnSeed(c.Seed), nil
	}
	if c.Legacy {
		return NewSimpleAuthenticator(), nil
	}
	return nil, nil
}

// GetHeaderType returns the header type
func (c *Config) GetHeaderType() string {
	if c.HeaderType == "" {
		return "none"
	}
	return c.HeaderType
}

// GetPacketHeader builds a new PacketHeader for this config.
func (c *Config) GetPacketHeader() PacketHeader {
	header, _ := NewPacketHeader(c.GetHeaderType())
	return header
}

func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.UplinkCapacity * 1024 * 1024 / c.MTU / (1000 / c.TTI)
	if size < 8 {
		size = 8
	}
	return size
}

// GetSendingBufferSize returns the sending window in segments.
func (c *Config) GetSendingBufferSize() uint32 {
	if c.MaxSendingWindow != 0 {
		return c.MaxSendingWindow / c.MTU
	}
	return c.GetWriteBufferSize() / c.MTU
}

func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.DownlinkCapacity * 1024 * 1024 / c.MTU / (1000 / c.TTI)
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetReceivingBufferSize() uint32 {
	return c.GetReadBufferSize() / c.MTU
}

func (c *Config) GetCwndMultiplier() uint32 {
	return c.CwndMultiplier
}
