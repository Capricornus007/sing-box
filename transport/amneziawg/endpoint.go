package amneziawg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	allowedIPs     *netipx.IPSet
	tunDevice      Device
	device         *device.Device
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	if len(privateKeyBytes) != 32 {
		return nil, E.New("invalid private key length")
	}
	amneziaLines, err := IpcLines(options.AmneziaWGObfuscationOptions)
	if err != nil {
		return nil, err
	}
	privateKey := hex.EncodeToString(privateKeyBytes)
	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	if amneziaLines != "" {
		ipcConf += "\n" + strings.TrimSuffix(amneziaLines, "\n")
	}
	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsFqdn() {
			peer.destination = rawPeer.Endpoint
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		if len(publicKeyBytes) != 32 {
			return nil, E.New("invalid public key length for peer ", peerIndex)
		}
		peer.publicKeyHex = hex.EncodeToString(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			if len(preSharedKeyBytes) != 32 {
				return nil, E.New("invalid pre shared key length for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		if len(rawPeer.Reserved) > 0 {
			if len(rawPeer.Reserved) != 3 {
				return nil, E.New("invalid reserved value for peer ", peerIndex, ", required 3 bytes, got ", len(peer.reserved))
			}
			copy(peer.reserved[:], rawPeer.Reserved[:])
			if peer.reserved != [3]uint8{} && amneziaLines != "" {
				return nil, E.New("reserved bytes cannot be combined with AmneziaWG obfuscation")
			}
		}
		peers = append(peers, peer)
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	deviceOptions := DeviceOptions{
		Context:        options.Context,
		Logger:         options.Logger,
		System:         options.System,
		Handler:        options.Handler,
		UDPTimeout:     options.UDPTimeout,
		CreateDialer:   options.CreateDialer,
		Name:           options.Name,
		MTU:            options.MTU,
		Address:        options.Address,
		AllowedAddress: allowedAddresses,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
		allowedIPs:     allowedIPSet,
		tunDevice:      tunDevice,
	}, nil
}

func (e *Endpoint) Start(resolve bool) error {
	if common.Any(e.peers, func(peer peerConfig) bool {
		return !peer.endpoint.IsValid() && peer.destination.IsFqdn()
	}) {
		if !resolve {
			return nil
		}
		for peerIndex, peer := range e.peers {
			if peer.endpoint.IsValid() || !peer.destination.IsFqdn() {
				continue
			}
			destinationAddress, err := e.options.ResolvePeer(peer.destination.Fqdn)
			if err != nil {
				return E.Cause(err, "resolve endpoint domain for peer[", peerIndex, "]: ", peer.destination)
			}
			e.peers[peerIndex].endpoint = netip.AddrPortFrom(destinationAddress, peer.destination.Port)
		}
	} else if resolve {
		return nil
	}
	var (
		isConnect   bool
		connectAddr netip.AddrPort
		reserved    [3]uint8
	)
	if len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
		isConnect = true
		connectAddr = e.peers[0].endpoint
		reserved = e.peers[0].reserved
	}
	bind := NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr, reserved)
	if len(e.peers) > 1 {
		for _, peer := range e.peers {
			if peer.reserved != [3]uint8{} {
				bind.SetReservedForEndpoint(peer.endpoint, peer.reserved)
			}
		}
	}
	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	wgDevice := device.NewDevice(e.tunDevice, bind, logger)
	e.tunDevice.SetDevice(wgDevice)
	ipcConf := e.ipcConf
	for _, peer := range e.peers {
		ipcConf += peer.GenerateIpcLines()
	}
	err = wgDevice.IpcSet(ipcConf)
	if err != nil {
		wgDevice.Close()
		return E.New("invalid AmneziaWG device configuration")
	}
	e.device = wgDevice
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := e.checkDestination(destination); err != nil {
		return nil, err
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	// An unspecified address only picks the address family of an unconnected socket, as the
	// client bind of a multi-peer WireGuard detoured through this endpoint requests. Its packets
	// still reach only destinations a peer accepts.
	if !destination.Addr.IsUnspecified() {
		if err := e.checkDestination(destination); err != nil {
			return nil, err
		}
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

// checkDestination rejects addresses no peer accepts. The device would drop their packets,
// so the dial would otherwise only fail after a timeout, and a serial dial over several
// resolved addresses would never reach one inside the allowed IPs.
func (e *Endpoint) checkDestination(destination M.Socksaddr) error {
	if !destination.Addr.IsValid() {
		return E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	if !e.allowedIPs.Contains(destination.Addr) {
		return E.New("destination ", destination.Addr, " is outside the allowed IPs")
	}
	return nil
}

func (e *Endpoint) Close() error {
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
	}
	if e.device != nil {
		e.device.Close()
	} else if e.tunDevice != nil {
		return e.tunDevice.Close()
	}
	return nil
}

func (e *Endpoint) onPauseUpdated(event int) {
	switch event {
	case pause.EventDevicePaused, pause.EventNetworkPause:
		e.device.Down()
	case pause.EventDeviceWake, pause.EventNetworkWake:
		e.device.Up()
	}
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
	reserved        [3]uint8
}

func (c peerConfig) GenerateIpcLines() string {
	ipcLines := "\npublic_key=" + c.publicKeyHex
	if c.endpoint.IsValid() {
		ipcLines += "\nendpoint=" + c.endpoint.String()
	}
	if c.preSharedKeyHex != "" {
		ipcLines += "\npreshared_key=" + c.preSharedKeyHex
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines += "\nallowed_ip=" + allowedIP.String()
	}
	if c.keepalive > 0 {
		ipcLines += "\npersistent_keepalive_interval=" + F.ToString(c.keepalive)
	}
	return ipcLines
}

// maxPacketSize is the largest UDP payload over IPv4; the device sends each junk and I1-I5 packet as one datagram.
const maxPacketSize = 65507

// maxJunkPacketCount is the most junk packets the device sends before a handshake; senders
// that write 128 packets per batch panic on more.
const maxJunkPacketCount = 128

// specialJunkFits adds up an I1-I5 tag chain the way the device sizes the packet. The device takes
// the lengths as they are: a negative one panics when the packet is built and a huge one allocates
// without bound. Tags the device cannot parse are left for it to report.
func specialJunkFits(spec string) bool {
	size := 0
	for rest := spec; ; {
		start := strings.IndexByte(rest, '<')
		if start < 0 {
			return true
		}
		end := strings.IndexByte(rest[start:], '>')
		if end < 0 {
			return true
		}
		fields := strings.Fields(rest[start+1 : start+end])
		rest = rest[start+end+1:]
		if len(fields) == 0 {
			continue
		}
		argument := ""
		if len(fields) > 1 {
			argument = fields[1]
		}
		switch fields[0] {
		case "b":
			size += len(strings.TrimPrefix(argument, "0x")) / 2
		case "t":
			size += 4
		case "r", "rc", "rd", "dz":
			length, err := strconv.Atoi(argument)
			if err != nil || length < 0 || length > maxPacketSize {
				return false
			}
			size += length
		}
		if size > maxPacketSize {
			return false
		}
	}
}

// IpcLines returns the AmneziaWG settings as wireguard-go UAPI lines, each ending in a
// newline. Zero values are left out, so a device without settings stays plain WireGuard.
func IpcLines(options option.AmneziaWGObfuscationOptions) (string, error) {
	for _, value := range []string{options.InitPacketMagicHeader, options.ResponsePacketMagicHeader, options.UnderloadPacketMagicHeader, options.TransportPacketMagicHeader, options.SpecialJunk1, options.SpecialJunk2, options.SpecialJunk3, options.SpecialJunk4, options.SpecialJunk5, options.ContentPaddingAddition, options.RekeyAfterTime, options.RekeyTimeout, options.RejectAfterTime, options.KeepaliveTimeout, options.MaxHandshakeAttempts} {
		if strings.ContainsAny(value, "\r\n") {
			return "", E.New("invalid line break in AmneziaWG parameter")
		}
	}
	for index, value := range []string{options.SpecialJunk1, options.SpecialJunk2, options.SpecialJunk3, options.SpecialJunk4, options.SpecialJunk5} {
		if !specialJunkFits(value) {
			return "", E.New("invalid AmneziaWG i", index+1, ": every length must be a whole number of bytes and the packet at most ", maxPacketSize, " bytes")
		}
	}
	if options.JunkPacketCount < 0 || options.JunkPacketCount > maxJunkPacketCount {
		return "", E.New("invalid AmneziaWG jc: at most ", maxJunkPacketCount, " junk packets")
	}
	// The device sizes junk packets from jmin and jmax as given: with jmin above jmax, including an
	// unset jmax, the unsigned size wraps around to gigabytes.
	if options.JunkPacketCount > 0 && (options.JunkPacketMinSize < 0 || options.JunkPacketMinSize > options.JunkPacketMaxSize || options.JunkPacketMaxSize > maxPacketSize) {
		return "", E.New("invalid AmneziaWG jmin and jmax: jmin must not exceed jmax, and jmax must be at most ", maxPacketSize, " bytes")
	}
	// S1 to S4 pad the handshake initiation, response, cookie reply and transport messages, and the device
	// sends each padded message as one datagram. It reads tunnel packets at offset 16+S4 into a 65535-byte
	// buffer, so a larger S4 crashes it.
	for index, padding := range []struct{ size, message int32 }{
		{options.InitPacketJunkSize, 148},
		{options.ResponsePacketJunkSize, 92},
		{options.CookieReplyPacketJunkSize, 64},
		{options.TransportPacketJunkSize, 32},
	} {
		if padding.size < 0 || padding.size > maxPacketSize-padding.message {
			return "", E.New("invalid AmneziaWG s", index+1, ": every padded message must fit ", maxPacketSize, " bytes")
		}
	}
	var headerProtectionKey string
	if options.HeaderProtectionKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(options.HeaderProtectionKey)
		if err != nil || len(keyBytes) != 32 {
			return "", E.New("invalid AmneziaWG header protection key")
		}
		headerProtectionKey = hex.EncodeToString(keyBytes)
	}
	var b strings.Builder
	addInt := func(key string, value int32) {
		if value != 0 {
			b.WriteString(key)
			b.WriteString("=")
			b.WriteString(F.ToString(value))
			b.WriteString("\n")
		}
	}
	addStr := func(key string, value string) {
		if value != "" {
			b.WriteString(key)
			b.WriteString("=")
			b.WriteString(value)
			b.WriteString("\n")
		}
	}
	addInt("jc", options.JunkPacketCount)
	addInt("jmin", options.JunkPacketMinSize)
	addInt("jmax", options.JunkPacketMaxSize)
	addInt("s1", options.InitPacketJunkSize)
	addInt("s2", options.ResponsePacketJunkSize)
	addInt("s3", options.CookieReplyPacketJunkSize)
	addInt("s4", options.TransportPacketJunkSize)
	addStr("h1", options.InitPacketMagicHeader)
	addStr("h2", options.ResponsePacketMagicHeader)
	addStr("h3", options.UnderloadPacketMagicHeader)
	addStr("h4", options.TransportPacketMagicHeader)
	addStr("i1", options.SpecialJunk1)
	addStr("i2", options.SpecialJunk2)
	addStr("i3", options.SpecialJunk3)
	addStr("i4", options.SpecialJunk4)
	addStr("i5", options.SpecialJunk5)
	addStr("header_protection_key", headerProtectionKey)
	addStr("content_padding_addition", options.ContentPaddingAddition)
	addStr("rekey_after_time", options.RekeyAfterTime)
	addStr("rekey_timeout", options.RekeyTimeout)
	addStr("reject_after_time", options.RejectAfterTime)
	addStr("keepalive_timeout", options.KeepaliveTimeout)
	addStr("max_handshake_attempts", options.MaxHandshakeAttempts)
	if options.RandomTrailers {
		addStr("random_trailers", "true")
	}
	if options.DisableCookies {
		addStr("disable_cookies", "true")
	}
	return b.String(), nil
}
