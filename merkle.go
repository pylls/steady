package steady

import (
	"math"
	"math/big"

	"github.com/pylls/steady/lc"
)

const (
	// LeafPrefix is the domain separation prefix for leaf hashes.
	LeafPrefix = 0x00

	// NodePrefix is the domain separation prefix for internal block nodes.
	NodePrefix = 0x01
)

// AuditPath as in RFC6962
func AuditPath(m int, data [][]byte) [][]byte {
	if len(data) <= 1 {
		return nil
	}
	// k is the largest power of two smaller than n (i.e., k < n <= 2k)
	k := int(math.Pow(2, float64(big.NewInt(int64(len(data)-1)).BitLen()-1)))
	if m < k {
		// PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])
		return append(AuditPath(m, data[:k]), MerkleTreeHash(data[k:]))
	} // index >= k
	// PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k])
	return append(AuditPath(m-k, data[k:]), MerkleTreeHash(data[:k]))
}

// RootFromAuditPath computes the expected root from an audit path
func RootFromAuditPath(l []byte, index, size int, path [][]byte) (r []byte) {
	r = lc.Hash([]byte{LeafPrefix}, l)
	lastIndex := size - 1
	for lastIndex > 0 {
		if index%2 == 1 {
			l, path = head(path)
			r = lc.Hash([]byte{NodePrefix}, l, r)
		} else if index < lastIndex {
			l, path = head(path)
			r = lc.Hash([]byte{NodePrefix}, r, l)
		}
		index = index / 2
		lastIndex = lastIndex / 2
	}
	return
}

func head(data [][]byte) (h []byte, tail [][]byte) {
	switch len(data) {
	case 0: // capturing nil, we do not need error checking in RootFromAuditPath
		return nil, nil
	case 1:
		return data[0], nil
	}
	return data[0], data[1:]
}

// MerkleTreeHash as in RFC6962
func MerkleTreeHash(data [][]byte) (root []byte) {
	switch len(data) {
	case 0: // MTH({}) = HASH()
		return lc.Hash([]byte{})
	case 1: // MTH({d(0)}) = HASH(0x00 || d(0))
		return lc.Hash([]byte{LeafPrefix}, data[0])
	}
	// MTH(D[n]) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])), where
	// k is the largest power of two smaller than n (i.e., k < n <= 2k)
	k := int(math.Pow(2, float64(big.NewInt(int64(len(data)-1)).BitLen()-1)))
	return lc.Hash([]byte{NodePrefix}, MerkleTreeHash(data[:k]),
		MerkleTreeHash(data[k:]))
}
