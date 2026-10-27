package amneziawg

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// PeerStatus is the live state of one peer. LastHandshake is zero until a handshake completes.
type PeerStatus struct {
	PublicKey                   string
	Endpoint                    string
	LastHandshake               time.Time
	RxBytes                     uint64
	TxBytes                     uint64
	PersistentKeepaliveInterval uint16
	AllowedIPs                  []netip.Prefix
}

func (e *Endpoint) PeerStatus() ([]PeerStatus, error) {
	if e.device == nil {
		return nil, E.New("device not started")
	}
	select {
	case <-e.device.Wait():
		return nil, E.New("device closed")
	default:
	}
	state, err := e.device.IpcGet()
	if err != nil {
		return nil, E.New("read device state")
	}
	return parsePeerStatus(state), nil
}

// parsePeerStatus copies an allowlist of peer fields out of a UAPI get response. The response
// also carries the private and preshared keys; those lines are skipped, so key material never
// leaves this function.
func parsePeerStatus(state string) []PeerStatus {
	var (
		peers         []PeerStatus
		handshakeSecs int64
	)
	for _, line := range strings.Split(state, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if key == "public_key" {
			var peer PeerStatus
			if publicKey, err := hex.DecodeString(value); err == nil {
				peer.PublicKey = base64.StdEncoding.EncodeToString(publicKey)
			}
			peers = append(peers, peer)
			handshakeSecs = 0
			continue
		}
		if len(peers) == 0 {
			continue
		}
		peer := &peers[len(peers)-1]
		switch key {
		case "endpoint":
			peer.Endpoint = value
		case "last_handshake_time_sec":
			handshakeSecs, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			handshakeNanos, _ := strconv.ParseInt(value, 10, 64)
			if handshakeSecs != 0 || handshakeNanos != 0 {
				peer.LastHandshake = time.Unix(handshakeSecs, handshakeNanos)
			}
		case "rx_bytes":
			peer.RxBytes, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			peer.TxBytes, _ = strconv.ParseUint(value, 10, 64)
		case "persistent_keepalive_interval":
			interval, _ := strconv.ParseUint(value, 10, 16)
			peer.PersistentKeepaliveInterval = uint16(interval)
		case "allowed_ip":
			if prefix, err := netip.ParsePrefix(value); err == nil {
				peer.AllowedIPs = append(peer.AllowedIPs, prefix)
			}
		}
	}
	return peers
}
