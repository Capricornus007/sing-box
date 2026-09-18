package route

import (
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/bufio"
)

func cachePacketBuffers(conn N.PacketConn, packetBuffers []*N.PacketBuffer) N.PacketConn {
	for i := len(packetBuffers) - 1; i >= 0; i-- {
		packetBuffer := packetBuffers[i]
		conn = bufio.NewCachedPacketConn(conn, packetBuffer.Buffer, packetBuffer.Destination)
		N.PutPacketBuffer(packetBuffer)
	}
	return conn
}
