package v2raykcp

import (
	"crypto/rand"
	"encoding/binary"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// dnsHeaderDomain is the query name Xray's mkcp-legacy dns header uses when none is set. Both
// sides strip a header of their own length, so the name must match the server's.
const dnsHeaderDomain = "www.baidu.com"

// used only by KCP to add an obfuscating header before encrypted payload.
type PacketHeader interface {
	Size() int
	Serialize([]byte)
}

// NewPacketHeader creates a new PacketHeader instance for the given header type: none, srtp,
// utp, wechat-video, dtls, wireguard or dns. None returns a nil header.
func NewPacketHeader(headerType string) (PacketHeader, error) {
	switch headerType {
	case "", "none":
		return nil, nil
	case "srtp":
		return newSRTPHeader(), nil
	case "utp":
		return newUTPHeader(), nil
	case "wechat-video":
		return newWechatVideoHeader(), nil
	case "dtls":
		return newDTLSHeader(), nil
	case "wireguard":
		return newWireguardHeader(), nil
	case "dns":
		return newDNSHeader(dnsHeaderDomain)
	default:
		return nil, E.New("unknown mKCP header type: ", headerType)
	}
}

// HeaderSize returns the byte size of the header for the given type.
func HeaderSize(headerType string) int {
	header, _ := NewPacketHeader(headerType)
	if header == nil {
		return 0
	}
	return header.Size()
}

// ----- DNS -----

// dnsHeader is a DNS query for an A record, with a random ID per packet.
type dnsHeader struct {
	header []byte
}

func newDNSHeader(domain string) (*dnsHeader, error) {
	header := []byte{0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if len(label) == 0 || len(label) >= 64 {
			return nil, E.New("invalid mKCP dns header domain: ", domain)
		}
		header = append(header, byte(len(label)))
		header = append(header, label...)
	}
	header = append(header, 0, 0, 1, 0, 1)
	return &dnsHeader{header: header}, nil
}

func (h *dnsHeader) Size() int {
	return len(h.header)
}

func (h *dnsHeader) Serialize(b []byte) {
	copy(b, h.header)
	binary.BigEndian.PutUint16(b, randomUint16())
}

// ----- SRTP -----

type srtpHeader struct {
	header uint16
	number uint16
}

func newSRTPHeader() *srtpHeader {
	return &srtpHeader{
		header: 0xB5E8,
		number: randomUint16(),
	}
}

func (*srtpHeader) Size() int {
	return 4
}

func (s *srtpHeader) Serialize(b []byte) {
	s.number++
	binary.BigEndian.PutUint16(b, s.header)
	binary.BigEndian.PutUint16(b[2:], s.number)
}

// ----- UTP -----

type utpHeader struct {
	header       byte
	extension    byte
	connectionID uint16
}

func newUTPHeader() *utpHeader {
	return &utpHeader{
		header:       1,
		extension:    0,
		connectionID: randomUint16(),
	}
}

func (*utpHeader) Size() int {
	return 4
}

func (u *utpHeader) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, u.connectionID)
	b[2] = u.header
	b[3] = u.extension
}

// ----- WeChat Video -----

type wechatVideoHeader struct {
	sn uint32
}

func newWechatVideoHeader() *wechatVideoHeader {
	return &wechatVideoHeader{
		sn: randomUint32(),
	}
}

func (*wechatVideoHeader) Size() int {
	return 13
}

func (vc *wechatVideoHeader) Serialize(b []byte) {
	vc.sn++
	b[0] = 0xa1
	b[1] = 0x08
	binary.BigEndian.PutUint32(b[2:], vc.sn)
	b[6] = 0x00
	b[7] = 0x10
	b[8] = 0x11
	b[9] = 0x18
	b[10] = 0x30
	b[11] = 0x22
	b[12] = 0x30
}

// ----- DTLS -----

type dtlsHeader struct {
	epoch    uint16
	length   uint16
	sequence uint32
}

func newDTLSHeader() *dtlsHeader {
	return &dtlsHeader{
		epoch:    randomUint16(),
		sequence: 0,
		length:   17,
	}
}

func (*dtlsHeader) Size() int {
	return 13
}

func (d *dtlsHeader) Serialize(b []byte) {
	b[0] = 23 // application data
	b[1] = 254
	b[2] = 253
	b[3] = byte(d.epoch >> 8)
	b[4] = byte(d.epoch)
	b[5] = 0
	b[6] = 0
	b[7] = byte(d.sequence >> 24)
	b[8] = byte(d.sequence >> 16)
	b[9] = byte(d.sequence >> 8)
	b[10] = byte(d.sequence)
	d.sequence++
	b[11] = byte(d.length >> 8)
	b[12] = byte(d.length)
	d.length += 17
	if d.length > 100 {
		d.length -= 50
	}
}

// ----- WireGuard -----

type wireguardHeader struct{}

func newWireguardHeader() *wireguardHeader {
	return &wireguardHeader{}
}

func (*wireguardHeader) Size() int {
	return 4
}

func (*wireguardHeader) Serialize(b []byte) {
	b[0] = 0x04
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}

// ----- helpers -----

func randomUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b[:])
}

func randomUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint32(b[:])
}
