package route

import (
	"slices"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

func cachePacketBuffers(conn N.PacketConn, packetBuffers []*N.PacketBuffer) N.PacketConn {
	for _, packetBuffer := range slices.Backward(packetBuffers) {

		conn = bufio.NewCachedPacketConn(conn, packetBuffer.Buffer, packetBuffer.Destination)
		N.PutPacketBuffer(packetBuffer)
	}
	return conn
}
