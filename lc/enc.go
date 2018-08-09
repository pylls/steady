package lc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	PublicKeySize   = 32
	PrivategKeySize = 32
)

func EncryptKeyGen() (pub, pk []byte, err error) {
	publicKey := new([32]byte)
	privateKey := new([32]byte)
	_, err = io.ReadFull(rand.Reader, privateKey[:])
	if err != nil {
		return
	}

	curve25519.ScalarBaseMult(publicKey, privateKey)
	return publicKey[:], privateKey[:], err
}

// Encrypt encrypts data, potentially overwriting the underlying data in the
// process!
func Encrypt(pub, data []byte) (ct []byte, err error) {
	var secret, ephmPub, ephmPk, public [32]byte
	if copy(public[:], pub) != 32 {
		return nil, fmt.Errorf("invalid public key")
	}
	_, err = io.ReadFull(rand.Reader, ephmPk[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %s", err)
	}

	// derive keymaterial
	curve25519.ScalarBaseMult(&ephmPub, &ephmPk)
	curve25519.ScalarMult(&secret, &ephmPk, &public)
	key := kdf(secret[:], pub, ephmPub[:], []byte("key"))
	nonce := kdf(secret[:], pub, ephmPub[:], []byte("nonce"))[:12]

	// AES-GCM with nonce from keyMaterial
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create block cipher: %s", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %s", err)
	}

	return append(aesgcm.Seal(data[:0], nonce, data, ephmPub[:]),
		ephmPub[:]...), nil
}

func kdf(secret, p1, p2, use []byte) []byte {
	return Hash(secret, p1, p2, use)
}

func Decrypt(ct, pub, pk []byte) (data []byte, err error) {
	var public, private, secret [32]byte
	if copy(private[:], pk) != 32 {
		return nil, fmt.Errorf("invalid private key")
	}
	if len(ct) < 32 {
		return nil, fmt.Errorf("too short ciphertext")
	}
	if copy(public[:], ct[len(ct)-32:]) != 32 {
		return nil, fmt.Errorf("invalid public key in ciphertext")
	}

	// derive keymaterial
	curve25519.ScalarMult(&secret, &private, &public)
	key := kdf(secret[:], pub, public[:], []byte("key"))
	nonce := kdf(secret[:], pub, public[:], []byte("nonce"))[:12]

	// AES-GCM with nonce from keyMaterial
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create block cipher: %s", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %s", err)
	}

	return aesgcm.Open(nil, nonce, ct[:len(ct)-32], public[:])
}
