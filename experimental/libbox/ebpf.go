//go:build with_ebpf && (linux || android)

package libbox

import (
	"encoding/json"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

// EBPFKernelProbeFinding 與 EBPFKernelProbeResult 是探針報告給 Kotlin 的形状。
// 刻意回 JSON 字串而不是 gomobile interface：這份報告的內容會隨內核能力增減，
// 綁成介面的話每加一個欄位都要兩邊一起改，而且它最終只是顯示給使用者看的診斷文字。
type EBPFKernelProbeFinding struct {
	Status     string `json:"status"`
	Scope      string `json:"scope"`
	Importance string `json:"importance"`
	Feature    string `json:"feature"`
	Detail     string `json:"detail"`
}

type EBPFKernelProbeResult struct {
	Supported     bool                     `json:"supported"`
	Platform      string                   `json:"platform"`
	KernelRelease string                   `json:"kernelRelease"`
	Architecture  string                   `json:"architecture"`
	Mode          string                   `json:"mode"`
	Error         string                   `json:"error,omitempty"`
	Failures      []EBPFKernelProbeFinding `json:"failures"`
	Warnings      []EBPFKernelProbeFinding `json:"warnings"`
	Counts        map[string]int           `json:"counts"`
}

// EBPFProbeKernel 真的去載入 BPF 程式試探，而不是比內核版本號。
// 差別很重要：廠商內核常把 bpf 特性回補卻不改 version，比版本號會誤殺能用的人；
// 反之號稱夠新但缺 CONFIG 的內核也會被放過。
//
// mode 取 "all"／"local"／"shared-network"，兩者是分開的能力：
// local 要 cgroup/connect4（4.17+），shared-network 只要 TC classifier（4.16+），
// 所以會出現「只能共網、不能本機」的中間態，UI 必須逐模式問。
func EBPFProbeKernel(mode string, cgroupPath string, interfaceName string) string {
	options := ECommon.KernelProbeOptions{
		Mode:          ECommon.KernelProbeMode(mode),
		CgroupPath:    cgroupPath,
		InterfaceName: interfaceName,
	}
	report, probeErr := ECommon.ProbeKernel(options)
	if probeErr != nil {
		return marshalProbeResult(&EBPFKernelProbeResult{
			Supported: false,
			Mode:      mode,
			Error:     probeErr.Error(),
		})
	}
	result := &EBPFKernelProbeResult{
		Supported:     report.RequiredFailures() == 0,
		Platform:      report.Platform,
		KernelRelease: report.KernelRelease,
		Architecture:  report.Architecture,
		Mode:          string(report.Mode),
		Failures:      make([]EBPFKernelProbeFinding, 0),
		Warnings:      make([]EBPFKernelProbeFinding, 0),
		Counts:        make(map[string]int),
	}
	for _, finding := range report.Findings {
		converted := EBPFKernelProbeFinding{
			Status:     string(finding.Status),
			Scope:      finding.Scope,
			Importance: string(finding.Importance),
			Feature:    finding.Feature,
			Detail:     finding.Detail,
		}
		if finding.Status == ECommon.KernelProbeFail && finding.Importance == ECommon.KernelProbeRequired {
			result.Failures = append(result.Failures, converted)
		} else if finding.Status == ECommon.KernelProbeFail || finding.Status == ECommon.KernelProbeWarn {
			result.Warnings = append(result.Warnings, converted)
		}
	}
	for status, count := range report.Counts() {
		result.Counts[string(status)] = count
	}
	if report.ActiveStateErr != nil {
		result.Error = report.ActiveStateErr.Error()
	}
	return marshalProbeResult(result)
}

func marshalProbeResult(result *EBPFKernelProbeResult) string {
	encoded, err := json.Marshal(result)
	if err != nil {
		return `{"supported":false,"error":"marshal probe result: ` + err.Error() + `"}`
	}
	return string(encoded)
}
