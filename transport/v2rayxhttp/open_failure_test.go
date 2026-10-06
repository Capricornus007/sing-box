package xhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type trackedStreamReader struct {
	io.Reader
	closed bool
}

func (r *trackedStreamReader) Close() error { r.closed = true; return nil }

type failingStreamClient struct {
	DialerClient
	calls, failAt int
	reader        *trackedStreamReader
}

func (c *failingStreamClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	c.calls++
	if c.calls == c.failAt {
		return nil, nil, nil, errors.New("open failed")
	}
	c.reader = &trackedStreamReader{Reader: strings.NewReader("")}
	return c.reader, nil, nil, nil
}

func TestFailedOpenReleasesStreamsAndUsage(t *testing.T) {
	for _, test := range []struct {
		mode   string
		failAt int
	}{{"stream-one", 1}, {"stream-up", 1}, {"stream-up", 2}} {
		transport := &failingStreamClient{failAt: test.failAt}
		usage := new(XmuxClient)
		getClient := func() (DialerClient, *XmuxClient, error) { return transport, usage, nil }
		client := Client{
			ctx:            context.Background(),
			options:        &option.V2RayXHTTPOptions{Mode: test.mode},
			getHTTPClient:  getClient,
			getHTTPClient2: getClient,
			logger:         log.NewNOPFactory().Logger(),
		}
		if _, err := client.DialContext(context.Background()); err == nil {
			t.Fatal("open unexpectedly succeeded")
		}
		if usage.GetOpenUsage() != 0 {
			t.Fatal("failed open retained xmux usage")
		}
		if transport.reader != nil && !transport.reader.closed {
			t.Fatal("download stream leaked")
		}
	}
}
