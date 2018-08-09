package steady

import (
	"bytes"
	"testing"

	"github.com/pylls/steady/lc"
	"github.com/stretchr/testify/assert"
)

func TestEncodePolicy(t *testing.T) {
	vk, sk, _ := lc.SigningKeyGen()
	pub, _, _ := lc.EncryptKeyGen()
	p := MakePolicy(sk, vk, pub, 0, 1, 2)
	b := EncodePolicy(p)
	assert.True(t, len(b) == WirePolicySize,
		"encoded policy not expected size, got %d, expected %d", len(b), WirePolicySize)

	p2, err := DecodePolicy(b)
	assert.Nil(t, err, "failed to decode policy: %v", err)
	assert.True(t, bytes.Equal(p.ID, p2.ID), "ID mismatch after encode and decode")
	assert.True(t, bytes.Equal(p.Pub, p2.Pub), "Pub mismatch after encode and decode")
	assert.True(t, bytes.Equal(p.Signature, p2.Signature), "Signature mismatch after encode and decode")
	assert.True(t, bytes.Equal(p.Vk, p2.Vk), "Vk mismatch after encode and decode")
	assert.True(t, p.Space == p2.Space, "Space mismatch after encode and decode")
	assert.True(t, p.Time == p2.Time, "Time mismatch after encode and decode")
	assert.True(t, p.Timeout == p2.Timeout, "Timeout mismatch after encode and decode")
}
