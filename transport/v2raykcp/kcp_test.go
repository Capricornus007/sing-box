package v2raykcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type echoHandler struct{}

func (echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func TestKCPRoundTrip(t *testing.T) {
	for name, options := range map[string]option.V2RayKCPOptions{
		"raw":         {},
		"legacy":      {Legacy: true},
		"seed":        {Seed: "kcp-seed"},
		"srtp":        {HeaderType: "srtp"},
		"utp":         {HeaderType: "utp"},
		"wechat":      {HeaderType: "wechat-video"},
		"dtls":        {HeaderType: "dtls"},
		"wireguard":   {HeaderType: "wireguard"},
		"dns":         {HeaderType: "dns"},
		"seed+dtls":   {HeaderType: "dtls", Seed: "kcp-seed"},
		"legacy+utp":  {HeaderType: "utp", Legacy: true},
		"small mtu":   {MTU: 576, TTI: 20},
		"cwnd window": {CwndMultiplier: 4, MaxSendingWindow: 1 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewServer(ctx, log.NewNOPFactory().Logger(), options, nil, echoHandler{})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go server.ServePacket(packetConn)

			client, err := NewClient(ctx, N.SystemDialer, M.SocksaddrFromNet(packetConn.LocalAddr()), options, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := client.DialContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := make([]byte, 256*1024)
			_, _ = rand.Read(payload)
			go conn.Write(payload)
			received := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, received); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, received) {
				t.Fatal("echo differs")
			}
		})
	}
}

// The connection outlives its dial context, and a deadline set while Read waits ends the wait
// with a net.Error timeout.
func TestKCPDialContextAndDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ctx, log.NewNOPFactory().Logger(), option.V2RayKCPOptions{}, nil, echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServePacket(packetConn)
	client, err := NewClient(ctx, N.SystemDialer, M.SocksaddrFromNet(packetConn.LocalAddr()), option.V2RayKCPOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dialCtx, dialCancel := context.WithCancel(ctx)
	conn, err := client.DialContext(dialCtx)
	dialCancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if err = conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
		t.Fatal("no echo after the dial context ended:", err)
	}

	_ = conn.SetReadDeadline(time.Time{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = conn.SetReadDeadline(time.Now())
	}()
	start := time.Now()
	_, err = conn.Read(reply)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal("expected a timeout, got", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatal("deadline woke Read after", elapsed)
	}
	if _, err = NewConfig(option.V2RayKCPOptions{MTU: 1500}); err == nil {
		t.Fatal("accepted an MTU Xray refuses")
	}
}

// Xray v26.2+ sends raw segments unless a mask is set; anything else would not reach its server.
func TestKCPWireFormat(t *testing.T) {
	ping := &CmdOnlySegment{Conv: 0x1234, Cmd: CommandPing}
	segment := make([]byte, ping.ByteSize())
	ping.Serialize(segment)
	cases := map[string]struct {
		options option.V2RayKCPOptions
		check   func(packet []byte) bool
	}{
		"raw":    {option.V2RayKCPOptions{}, func(p []byte) bool { return bytes.Equal(p, segment) }},
		"legacy": {option.V2RayKCPOptions{Legacy: true}, func(p []byte) bool { return len(p) == len(segment)+6 }},
		"seed":   {option.V2RayKCPOptions{Seed: "x"}, func(p []byte) bool { return len(p) == len(segment)+12+16 }},
		"dns":    {option.V2RayKCPOptions{HeaderType: "dns"}, func(p []byte) bool { return len(p) == 31+len(segment) && bytes.Equal(p[31:], segment) }},
		"wechat": {option.V2RayKCPOptions{HeaderType: "wechat-video"}, func(p []byte) bool { return len(p) == 13+len(segment) && p[0] == 0xa1 }},
	}
	for name, c := range cases {
		config, err := NewConfig(c.options)
		if err != nil {
			t.Fatal(name, err)
		}
		security, _ := config.GetSecurity()
		local, remote := net.Pipe()
		_ = remote
		var captured []byte
		writer := &kcpPacketWriter{conn: capturePacketConn{local, &captured}, remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, header: config.GetPacketHeader(), security: security}
		if _, err = writer.Write(segment); err != nil {
			t.Fatal(name, err)
		}
		if !c.check(captured) {
			t.Fatalf("%s: unexpected packet %x", name, captured)
		}
		reader := &kcpPacketReader{security: security, headerSize: HeaderSize(config.GetHeaderType())}
		if segments := reader.Read(captured); len(segments) != 1 || segments[0].Command() != CommandPing {
			t.Fatalf("%s: packet does not read back", name)
		}
	}
	if _, err := NewConfig(option.V2RayKCPOptions{HeaderType: "unknown"}); err == nil {
		t.Fatal("accepted an unknown header type")
	}
}

// capturePacketConn records the last packet written to it.
type capturePacketConn struct {
	net.Conn
	out *[]byte
}

func (c capturePacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func (c capturePacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	*c.out = append([]byte(nil), buffer.Bytes()...)
	return nil
}
