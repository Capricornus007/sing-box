package xhttp

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	X "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type errorReadCloser struct {
	io.Reader
	err error
}

func (r errorReadCloser) Close() error { return r.err }

func TestSplitCloseReportsReaderError(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	sentinel := errors.New("reader close")
	conn := splitConn{writer: writer, reader: errorReadCloser{strings.NewReader(""), sentinel}}
	if !errors.Is(conn.Close(), sentinel) {
		t.Fatal("reader error lost")
	}
}

func TestPacketLimitRejectedBeforeDial(t *testing.T) {
	options := option.V2RayXHTTPOptions{V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{ScMaxEachPostBytes: &X.Range{}}}
	if _, err := NewClient(context.Background(), nil, M.Socksaddr{}, options, nil); err == nil {
		t.Fatal("zero packet limit accepted")
	}
}

func TestPaddingWithPowerOfTwoAlphabet(t *testing.T) {
	result := make(chan string, 1)
	go func() { value, _ := randStringFromCharset(16, "01"); result <- value }()
	select {
	case value := <-result:
		if len(value) != 16 || strings.Trim(value, "01") != "" {
			t.Fatal(value)
		}
	case <-time.After(time.Second):
		t.Fatal("padding generator did not terminate")
	}
}

func TestUploadQueueCloseUnblocksFullPushAndReader(t *testing.T) {
	for range 30 {
		queue := NewUploadQueue(1)
		if err := queue.Push(Packet{Payload: []byte{1}}); err != nil {
			t.Fatal(err)
		}
		pushed := make(chan error, 1)
		go func() { pushed <- queue.Push(Packet{Seq: 1, Payload: []byte{2}}) }()
		closed := make(chan struct{})
		go func() { queue.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("close blocked behind a full queue")
		}
		select {
		case err := <-pushed:
			if err == nil {
				t.Fatal("push succeeded after close")
			}
		case <-time.After(time.Second):
			t.Fatal("push remained blocked")
		}

		queue = NewUploadQueue(1)
		reader, writer := io.Pipe()
		if err := queue.Push(Packet{Reader: reader}); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func(q *uploadQueue) { _, err := q.Read(make([]byte, 1)); result <- err }(queue)
		queue.Close()
		writer.Close()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("read succeeded after close")
			}
		case <-time.After(time.Second):
			t.Fatal("reader remained blocked")
		}
	}
}
