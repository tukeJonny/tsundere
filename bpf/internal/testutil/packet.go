package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/google/gopacket"
)

func SerializePacket(t *testing.T, layers ...gopacket.SerializableLayer) []byte {
	var (
		buf = gopacket.NewSerializeBuffer()
		opts = gopacket.SerializeOptions{
			ComputeChecksums: true,
		}
	)
	err := gopacket.SerializeLayers(buf, opts, layers...)
	assert.NoError(t, err)

	return buf.Bytes()
}


