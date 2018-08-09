package lc

import "golang.org/x/crypto/blake2b"

const (
	HashOutputLen = 32
)

// Hash hashes the data.
func Hash(data ...[]byte) []byte {
	hasher, _ := blake2b.New256(nil) // cannot error on nil key
	for i := 0; i < len(data); i++ {
		hasher.Write(data[i])
	}
	return hasher.Sum(nil)
}

// Khash hashes the data with a key.
func Khash(key []byte, data ...[]byte) []byte {
	if len(key) > 64 { // ensure we cannot error
		key = key[:64]
	}
	hasher, _ := blake2b.New256(key)
	for i := 0; i < len(data); i++ {
		hasher.Write(data[i])
	}
	return hasher.Sum(nil)
}
