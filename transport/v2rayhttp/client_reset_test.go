package v2rayhttp_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2raygrpclite"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	xhttp "github.com/sagernet/sing-box/transport/v2rayxhttp"
	M "github.com/sagernet/sing/common/metadata"
)

type loopbackDialer struct{ net.Dialer }

func (d *loopbackDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, address.String())
}

func (*loopbackDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestResetClosesActiveHTTP2StreamsAndAllowsReconnect(t *testing.T) {
	for _, protocol := range []string{"http", "grpc", "xhttp"} {
		t.Run(protocol, func(t *testing.T) {
			requests := make(chan (<-chan struct{}), 2)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Error("expected HTTP/2")
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				requests <- r.Context().Done()
				<-r.Context().Done()
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tlsConfig, err := tls.NewClient(ctx, log.NewNOPFactory().Logger(), "localhost", option.OutboundTLSOptions{Enabled: true, Insecure: true})
			if err != nil {
				t.Fatal(err)
			}
			address := M.ParseSocksaddr(server.Listener.Addr().String())
			var transport adapter.V2RayClientTransport
			switch protocol {
			case "http":
				transport, err = v2rayhttp.NewClient(ctx, &loopbackDialer{}, address, option.V2RayHTTPOptions{}, tlsConfig)
				if err != nil {
					t.Fatal(err)
				}
			case "grpc":
				transport = v2raygrpclite.NewClient(ctx, &loopbackDialer{}, address, option.V2RayGRPCOptions{}, tlsConfig)
			default:
				transport, err = xhttp.NewClient(ctx, log.NewNOPFactory().Logger(), &loopbackDialer{}, address, option.V2RayXHTTPOptions{Mode: "stream-one"}, tlsConfig)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer transport.Close()
			for range 2 {
				_, err := transport.DialContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var done <-chan struct{}
				select {
				case done = <-requests:
				case <-ctx.Done():
					t.Fatal("request never reached HTTP/2 server")
				}
				if err := transport.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("active stream survived reset")
				}
			}
		})
	}
}
