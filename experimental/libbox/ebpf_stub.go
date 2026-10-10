//go:build !(with_ebpf && (linux || android))

package libbox

// 沒有 with_ebpf 時也要有這個符號：gomobile 綁定是照「導出名」產生 Java 介面的，
// 缺了它整個 LibCore 綁定就會少一個方法、Kotlin 側直接編不過，
// 而不是只讓 eBPF 功能消失。
func EBPFProbeKernel(mode string, cgroupPath string, interfaceName string) string {
	return `{"supported":false,"error":"eBPF requires the with_ebpf build tag on linux/android"}`
}
