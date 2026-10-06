package anytls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	testFrameHeaderSize = 7
	testCommandSettings = 4
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
						var header [testFrameHeaderSize]byte
						if _, err := io.ReadFull(serverConn, header[:]); err != nil {
							return err
						}
						data := make([]byte, binary.BigEndian.Uint16(header[5:]))
						if _, err := io.ReadFull(serverConn, data); err != nil {
							return err
						}
						if header[0] == testCommandSettings {
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
			h := &Outbound{logger: log.NewNOPFactory().Logger(), clientOptions: anytls.ClientOptions{
				Password:       "example-password",
				ClientMetadata: metadata,
				Logger:         log.NewNOPFactory().Logger(),
				DialOut:        func(context.Context) (net.Conn, error) { return clientConn, nil },
			}}
			scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
			if err := h.Start(adapter.StartStateInitialize, scope); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = scope.Close() }()
			destination := M.ParseSocksaddr("example.invalid:443")
			stream, err := h.client.DialContext(context.Background(), destination)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			// 本倉使用的 sing-anytls 把目的地放在首次寫入觸發的 PSH 幀（SYN 本身 length=0），
			// 所以要寫一-byte 才會看到 destination；設定幀在撥號時就已發出。
			if _, err = stream.Write([]byte{0x00}); err != nil {
				t.Fatal(err)
			}
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
