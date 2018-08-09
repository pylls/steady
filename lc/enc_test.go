package lc

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	pub, pk, err := EncryptKeyGen()
	assert.Nil(t, err, "got error when generation encryption key-pair")
	data := []byte("secret message")
	ct, err := Encrypt(pub, data)
	assert.Nil(t, err, "failed to encrypt")
	pt, err := Decrypt(ct, pub, pk)
	assert.Nil(t, err, "failed to decrypt")
	assert.True(t, bytes.Equal(data, pt), "decrypt gave different plaintext")
}
