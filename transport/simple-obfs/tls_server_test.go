package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

type inputConn struct {
	net.Conn
	input *bytes.Reader
}

func (c inputConn) Read(b []byte) (int, error) { return c.input.Read(b) }

func TestTLSObfsTruncatedRecordLengthReturnsError(t *testing.T) {
	server := TLSObfsServer{Conn: inputConn{input: bytes.NewReader([]byte{0})}}
	if _, err := server.read(make([]byte, 8), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("missing record error", err)
	}
}
