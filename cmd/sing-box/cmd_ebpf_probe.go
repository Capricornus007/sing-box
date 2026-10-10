//go:build with_ebpf && (linux || android)

package main

import (
	"os"

	EBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	ebpfProbeMode      string
	ebpfProbeCgroup    string
	ebpfProbeInterface string
)

var commandEBPFProbe = &cobra.Command{
	Use:   "ebpf-probe",
	Short: "Probe kernel capabilities required by the eBPF inbound and print JSON",
	Run:   ebpfProbe,
	Args:  cobra.NoArgs,
}

func init() {
	commandEBPFProbe.Flags().StringVar(&ebpfProbeMode, "mode", "all", "all, local or shared-network")
	commandEBPFProbe.Flags().StringVar(&ebpfProbeCgroup, "cgroup", "", "cgroup to attach to, empty uses the default")
	commandEBPFProbe.Flags().StringVar(&ebpfProbeInterface, "interface", "", "interface for the shared-network path")
	mainCommand.AddCommand(commandEBPFProbe)
}

// 探針真的去載入 BPF 程式，而不是比內核版本號：廠商內核常把 bpf 特性回補卻不改 version
// 號（比版本號會誤殺能用的人），反之號稱夠新但缺 CONFIG 的也会被放過。
//
// 退出碼固定 0，只要探針本身跑完了就是 0，判定寫在 JSON 的 result 裡。理由：這支命令的
// 存在理由是給 app 讀的，「內核不支持」是一個正常答案，不是一個錯誤；如果把它做成非零，
// 呼叫端就分不出「內核不行」跟「探針壞了／參數打錯」，而後者才需要報修。
func ebpfProbe(cmd *cobra.Command, args []string) {
	report, err := EBPF.ProbeKernel(EBPF.KernelProbeOptions{
		Mode:          EBPF.KernelProbeMode(ebpfProbeMode),
		CgroupPath:    ebpfProbeCgroup,
		InterfaceName: ebpfProbeInterface,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = EBPF.WriteKernelProbeReportJSON(os.Stdout, report)
	if err != nil {
		log.Fatal(err)
	}
}
