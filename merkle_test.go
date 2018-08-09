package steady

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/pylls/steady/lc"
	"github.com/stretchr/testify/assert"
)

func TestMerkleTreeHash(t *testing.T) {
	data := make([][]byte, 0)
	for index, a := range googleTestLeaves() {
		data = append(data, a)
		assert.True(t, bytes.Equal(MerkleTreeHash(data),
			googleRootForTestLeaves(index)), "fail for index %d, expected %s, got %s",
			index, googleRootForTestLeaves(index), hex.EncodeToString(MerkleTreeHash(data)))
	}
}

// test leaves from Google's CT implementation at:
// https://github.com/google/certificate-transparency/data/
// 52da6fd97058b48ac67a559a734b970fd0e429e4/go/merkletree/merkle_tree_test.go
// (Apache 2.0)
func googleTestLeaves() [][]byte {
	return [][]byte{{},
		{0x00},
		{0x10},
		{0x20, 0x21},
		{0x30, 0x31},
		{0x40, 0x41, 0x42, 0x43},
		{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
		{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f}}
}

// corresponding correct values from Google, recalculated for Blake2b256
func googleRootForTestLeaves(numLeaves int) []byte {
	switch numLeaves {
	case 0:
		return mustDecode("03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314")
	case 1:
		return mustDecode("607844f4b0299f5c45d63dd035de1f8d697711c7f092b8fa82325f670f6d386a")
	case 2:
		return mustDecode("6ee5d7ded74104b2316b73f9843e14d16d9c5f553a39cbd7da7c3c8238fe0b0e")
	case 3:
		return mustDecode("dad1013557a71536d36ab10db2ea4847bed7ded78aa9d2682ffc0e221e758444")
	case 4:
		return mustDecode("a69507075082f2f7bd0e3e23bd31d7082c4c78ce98d87d897f7990eecf7d6ec5")
	case 5:
		return mustDecode("76840409bd8cc8be20c053d9569472d0bbea7b4f483cd5ae0624ef253c64f227")
	case 6:
		return mustDecode("ae8349a901b95ac305157e4ff4f5cf486653fed085ea4dd59a59c9375682933e")
	case 7:
		return mustDecode("59cc7108743d34853ea37ea07558da3407712c7f0fdb76e59753eb243e0c438e")
	default:
		panic("unexpected number of leaves")
	}
}

// source: Google's CT implementation
func mustDecode(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TestAuditPath(t *testing.T) {
	data := make([][]byte, 0)
	for _, a := range googleTestLeaves() {
		data = append(data, a)
		for i := 0; i < len(data); i++ {
			assert.True(t, bytes.Equal(MerkleTreeHash(data),
				RootFromAuditPath(data[i], i, len(data), AuditPath(i, data))),
				"fail for index %d", i)
		}
	}
	assert.False(t, bytes.Equal(MerkleTreeHash(data),
		RootFromAuditPath(nil, 0, len(data), nil)), "verified an empty audit path")
	assert.False(t, bytes.Equal(MerkleTreeHash(data),
		RootFromAuditPath(nil, len(data)-1, len(data), AuditPath(0, data))),
		"verified audit path with wrong index")
}

func BenchmarkMerkleTreeHash(b *testing.B) {
	data := make([][]byte, 0)
	for _, a := range googleTestLeaves() {
		data = append(data, a)
	}

	for i := 0; i < b.N; i++ {
		MerkleTreeHash(data)
	}
}

func BenchmarkHashDefault(b *testing.B) {
	data := lc.Hash([]byte("hello world"))
	for i := 0; i < b.N; i++ {
		lc.Hash(data)
	}
}
