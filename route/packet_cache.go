package route

import (
	"slices"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

func cachePacketBuffers(conn N.PacketConn, packetBuffers []*N.PacketBuffer) N.PacketConn {
	for _, packetBuffer := range slices.Backward(packetBuffers) {
		// Buffer 為 nil 代表這塊**已經歸還過了**。這裡刻意跳過而不是照舊包一層：
		// `bufio.NewCachedPacketConn` 第一行就是 `buffer.IncRef()`，拿 nil 進去就是
		// 空指標 panic → Go 執行期自我 SIGABRT（裝置端 102 筆 tombstone 全長成
		// 「兩格 unknown、沒有 Abort message」就是這個樣子）。
		//
		// 由來：UDP 路由裡同一批緩衝被處理兩遍（一段內聯迴圈 Put ＋ 這裡再 Put）
		// 10-05 修過（d468ba640）、10-09 吃 upstream/testing 合併又把它撿回來
		// （67a13e407）、10-10 再修（c1dfeafd）。既然「吃上游就會再回來」，
		// 這裡就不能只靠「記得別寫兩遍」——上游那條內聯迴圈哪天又出現時，
		// 這道跳過讓它變成無害，而不是讓整個 :bg 進程崩掉。
		if packetBuffer == nil || packetBuffer.Buffer == nil {
			continue
		}
		conn = bufio.NewCachedPacketConn(conn, packetBuffer.Buffer, packetBuffer.Destination)
		N.PutPacketBuffer(packetBuffer)
	}
	return conn
}
