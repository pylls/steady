package steady

import (
	"bytes"
	"testing"
	"time"

	"github.com/pylls/steady/lc"
	"github.com/stretchr/testify/assert"
)

func TestMakeBlock(t *testing.T) {
	vk, sk, _ := lc.SigningKeyGen()
	pub, pk, _ := lc.EncryptKeyGen()
	p := MakePolicy(sk, vk, pub, 0, 1, 2)

	var prevSize uint64
	for i, events := range [][][]byte{nil, {{}},
		{{0x12, 0x34}, {0x34, 0x12, 0x56}},
		{{0x20, 0x21}, {0x30, 0x31}}} {
		enc := i%2 == 0
		comp := i%3 == 0
		block, err := MakeEncodedBlock(uint64(i), prevSize, uint64(time.Now().Unix()), enc, comp, p, events, sk)
		assert.Nil(t, err, "failed to make encoded block: %s", err)

		bh, err := DecodeBlockHeader(block[:WireBlockHeaderSize], p)
		assert.Nil(t, err, "failed to decode valid header: %s", err)

		recEvents, _, err := DecodeBlockPayload(block[WireBlockHeaderSize:], pub, pk, p, bh)
		assert.Nil(t, err, "failed to decode valid payload: %s", err)
		assert.True(t, len(recEvents) == len(events), "received different number of events")
		for j := 0; j < len(events); j++ {
			assert.True(t, bytes.Equal(recEvents[j], events[j]), "received different event")
		}
	}
}
