package anytls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

func TestClientMetadataOnWire(t *testing.T) {
	for _, metadata := range []string{"", "example-client"} {
		t.Run("metadata="+metadata, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()
			serverConn.SetDeadline(time.Now().Add(5 * time.Second))
			type result struct {
				settings    string
				destination M.Socksaddr
				err         error
			}
			results := make(chan result, 1)
			go func() {
				var captured result
				captured.err = func() error {
					var authentication [34]byte
					if _, err := io.ReadFull(serverConn, authentication[:]); err != nil {
						return err
					}
					if _, err := io.CopyN(io.Discard, serverConn, int64(binary.BigEndian.Uint16(authentication[32:]))); err != nil {
						return err
					}
					for {
						var header [frameHeaderSize]byte
						if _, err := io.ReadFull(serverConn, header[:]); err != nil {
							return err
						}
						data := make([]byte, binary.BigEndian.Uint16(header[5:]))
						if _, err := io.ReadFull(serverConn, data); err != nil {
							return err
						}
						if header[0] == commandSettings {
							captured.settings = string(data)
						}
						if header[0] == 2 { // PSH contains the destination, after settings and SYN.
							var err error
							captured.destination, err = M.SocksaddrSerializer.ReadAddrPort(strings.NewReader(string(data)))
							return err
						}
					}
				}()
				results <- captured
				io.Copy(io.Discard, serverConn)
			}()
			h := &Outbound{ctx: context.Background(), clientMetadata: metadata, clientOptions: anytls.ClientConfig{
				Password: "example-password",
				Logger:   log.NewNOPFactory().Logger(),
				DialOut:  func(context.Context) (net.Conn, error) { return clientConn, nil },
			}}
			if err := h.Start(adapter.StartStateInitialize); err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			destination := M.ParseSocksaddr("example.invalid:443")
			stream, err := h.createProxy(context.Background(), destination)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			captured := <-results
			if captured.err != nil {
				t.Fatal(captured.err)
			}
			settings := make(map[string]string)
			for _, line := range strings.Split(captured.settings, "\n") {
				key, value, _ := strings.Cut(line, "=")
				settings[key] = value
			}
			if value, present := settings["client"]; !present || value != metadata {
				t.Fatalf("unexpected client metadata: %q", value)
			}
			if settings["v"] != "2" || settings["padding-md5"] == "" {
				t.Fatal("protocol settings lost")
			}
			if captured.destination != destination {
				t.Fatal("destination frame changed")
			}
		})
	}
}
