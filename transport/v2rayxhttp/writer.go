package xhttp

import (
	"sync/atomic"

	xray "github.com/sagernet/sing-box/common/xray"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/common/xray/pipe"
	E "github.com/sagernet/sing/common/exceptions"
)

// A wrapper around pipe that ensures the size limit is exactly honored.
//
// The MultiBuffer pipe accepts any single WriteMultiBuffer call even if that
// single MultiBuffer exceeds the size limit, and then starts blocking on the
// next WriteMultiBuffer call. This means that ReadMultiBuffer can return more
// bytes than the size limit. We work around this by splitting a potentially
// too large write up into multiple.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
	cause  *atomic.Pointer[error]
}

func (w uploadWriter) Write(b []byte) (int, error) {
	/*
		capacity := int(w.maxLen - w.Len())
		if capacity > 0 && capacity < len(b) {
			b = b[:capacity]
		}
	*/
	buffer := buf.MultiBufferContainer{}
	xray.Must2(buffer.Write(b))

	var writed int
	for _, buff := range buffer.MultiBuffer {
		bufferLen := int(buff.Len())
		if err := w.WriteMultiBuffer(buf.MultiBuffer{buff}); err != nil {
			return writed, w.explain(err)
		}
		writed += bufferLen
	}
	return writed, nil
}

// 上傳那側一旦中斷，pipe 只會回 `io.ErrClosedPipe`，呼叫端分不出是 POST 失敗、
// 還是 xmux 拿不出可用客戶端——那兩種在排障上完全不同。中斷前把真正的錯存進
// cause，這裡就把它接回錯誤鏈。
func (w uploadWriter) explain(err error) error {
	if w.cause != nil {
		if cause := w.cause.Load(); cause != nil {
			return E.Cause(err, *cause)
		}
	}
	return err
}
