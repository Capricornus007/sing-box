package encryption

import (
	"errors"
	"io"
	"net"
	"testing"
)

type failingWriter struct {
	net.Conn
	writes int
	err    error
}

func (w *failingWriter) Write(b []byte) (int, error) {
	w.writes++
	if w.writes == 2 {
		return 0, w.err
	}
	return len(b), nil
}

func TestWriteRetainsCompletedPayloadCount(t *testing.T) {
	for _, failure := range []error{errors.New("write failed"), nil} {
		raw := &failingWriter{err: failure}
		conn := NewCommonConn(raw, true)
		conn.AEAD = NewAEAD([]byte("example"), []byte("example-key"), true)
		n, err := conn.Write(make([]byte, 8193))
		if failure == nil {
			failure = io.ErrShortWrite
		}
		if n != 8192 || !errors.Is(err, failure) {
			t.Fatal(n, err)
		}
	}
}
