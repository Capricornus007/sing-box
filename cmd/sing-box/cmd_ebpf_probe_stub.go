//go:build !(with_ebpf && (linux || android))

package main

import (
	"os"

	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var commandEBPFProbe = &cobra.Command{
	Use:   "ebpf-probe",
	Short: "Probe kernel capabilities required by the eBPF inbound and print JSON",
	Run:   ebpfProbe,
	Args:  cobra.NoArgs,
}

func init() {
	mainCommand.AddCommand(commandEBPFProbe)
}

// 這顆命令在「沒帶 with_ebpf 的建置」與「非 Linux/Android 平台」上也必須存在，而且回同一個
// result 欄位。理由：呼叫端（NB4A 的第三條路 UI）是靠 `su -c libsingbox.so ebpf-probe` 的
// stdout 判斷能力，一旦命令不存在，它拿到的是 cobra 的 usage 文字而不是 JSON，UI 只能顯示
// 「探針沒回應」——那跟「內核不支持」是兩件事，混在一起就會把「這支 binary 少編了 tag」
// 這種我方建置缺陷，講成用戶裝置不行。
func ebpfProbe(cmd *cobra.Command, args []string) {
	_, err := os.Stdout.WriteString("{\n  \"result\": \"unsupported\",\n  \"error\": \"this sing-box binary was built without the with_ebpf tag or for a platform other than linux/android\"\n}\n")
	if err != nil {
		log.Fatal(err)
	}
}
