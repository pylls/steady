package steady

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pylls/steady/lc"
)

type Policy struct {
	ID, Signature, Vk, Pub []byte
	Timeout, Space, Time   uint64
}

func MakePolicy(sk, vk, pub []byte,
	timeout, space, time uint64) Policy {
	id := make([]byte, WireIdentifierSize)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		panic(err)
	}

	p := Policy{
		ID:      id,
		Vk:      vk,
		Pub:     pub,
		Timeout: timeout,
		Space:   space,
		Time:    time,
	}
	buf := make([]byte, 0, WirePolicySize-lc.SignatureSize)
	buf = encodePolicy(p, buf)
	p.Signature = lc.Sign(sk, buf)
	return p
}

func encodePolicy(p Policy, b []byte) []byte {
	b = append(b, p.ID...)
	b = append(b, p.Vk...)
	b = append(b, p.Pub...)

	tmp := make([]byte, 3*8)
	binary.BigEndian.PutUint64(tmp, p.Timeout)
	binary.BigEndian.PutUint64(tmp[8:], p.Space)
	binary.BigEndian.PutUint64(tmp[16:], p.Time)
	return append(b, tmp...)
}

func EncodePolicy(p Policy) []byte {
	b := make([]byte, 0, WirePolicySize)
	b = encodePolicy(p, b)

	return append(b, p.Signature...)
}

func DecodePolicy(b []byte) (Policy, error) {
	var p Policy
	if len(b) != WirePolicySize {
		return p, fmt.Errorf("invalid encoded policy length, expected %d, got %d",
			WirePolicySize, len(b))
	}
	if !lc.Verify(b[WireIdentifierSize:WireIdentifierSize+lc.VericationKeySize],
		b[:WirePolicySize-lc.SignatureSize], b[WirePolicySize-lc.SignatureSize:]) {
		return p, fmt.Errorf("invalid signature in Policy")
	}

	copied := 0
	p.ID = make([]byte, WireIdentifierSize)
	copied += copy(p.ID, b[copied:])
	p.Vk = make([]byte, lc.VericationKeySize)
	copied += copy(p.Vk, b[copied:])
	p.Pub = make([]byte, lc.PublicKeySize)
	copied += copy(p.Pub, b[copied:])
	p.Timeout = binary.BigEndian.Uint64(b[copied:])
	copied += 8
	p.Space = binary.BigEndian.Uint64(b[copied:])
	copied += 8
	p.Time = binary.BigEndian.Uint64(b[copied:])
	copied += 8
	p.Signature = make([]byte, lc.SignatureSize)
	copied += copy(p.Signature, b[copied:])

	return p, nil
}
