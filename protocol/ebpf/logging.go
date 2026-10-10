//go:build with_ebpf && (linux || android)

package ebpf

import (
	"fmt"

	"github.com/sagernet/sing-box/log"
)

// mihomo 的 log.Xxxln 是 printf 語意，我方 log 是 Print 語意，
// 直接改名會讓 %v/%s 原樣印進日誌，所以保留這層格式化適配。
func logDebugf(format string, args ...any) {
	log.Debug(fmt.Sprintf(format, args...))
}

func logInfof(format string, args ...any) {
	log.Info(fmt.Sprintf(format, args...))
}

func logWarnf(format string, args ...any) {
	log.Warn(fmt.Sprintf(format, args...))
}

func logErrorf(format string, args ...any) {
	log.Error(fmt.Sprintf(format, args...))
}
