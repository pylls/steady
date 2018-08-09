package lc

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"
)

const (
	VericationKeySize = 32
	SigningKeySize    = 64
	SignatureSize     = 64
)

func SigningKeyGen() (vk, sk []byte, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

func Sign(sk, msg []byte) []byte {
	return ed25519.Sign(sk, msg)
}

func Verify(vk, msg, signature []byte) bool {
	return ed25519.Verify(vk, msg, signature)
}
