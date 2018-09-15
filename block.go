package steady

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pylls/steady/lc"
)

// IVsize is the number of bytes of the random IV per block.
const IVsize = 32

type BlockHeader struct {
	Index, LenCur, LenPrev, Time                 uint64
	PayloadHash, HeaderHash, RootHash, Signature []byte
	Encrypted, Compressed                        bool
}

func MakeEncodedBlock(index, lenPrev, time uint64,
	encrypt, compress bool,
	policy Policy, events [][]byte, sk []byte) ([]byte, error) {
	payload, payloadHash, rootHash, err := packData(events, policy, encrypt, compress)
	if err != nil {
		return nil, err
	}

	// calculate the total current length (size in bytes) of this block
	lenCur := uint64(WireBlockHeaderSize + len(payload))

	// generate the header hash
	tmp := make([]byte, 3*8+lc.HashOutputLen)
	binary.BigEndian.PutUint64(tmp, index)
	binary.BigEndian.PutUint64(tmp[8:], lenCur)
	binary.BigEndian.PutUint64(tmp[16:], lenPrev)
	copy(tmp[24:], payloadHash)
	if encrypt {
		tmp = append(tmp, WireTrue)
	} else {
		tmp = append(tmp, WireFalse)
	}
	if compress {
		tmp = append(tmp, WireTrue)
	} else {
		tmp = append(tmp, WireFalse)
	}
	headerHash := lc.Khash(policy.ID, tmp)

	// sign headerHash + rootHash + time
	tmp = make([]byte, lc.HashOutputLen*2+8)
	copy(tmp, headerHash)
	copy(tmp[lc.HashOutputLen:], rootHash)
	binary.BigEndian.PutUint64(tmp[lc.HashOutputLen*2:], time)
	signature := lc.Sign(sk, tmp)

	// put together encoded block
	tmp = make([]byte, lenCur)
	binary.BigEndian.PutUint64(tmp, index)
	binary.BigEndian.PutUint64(tmp[8:], lenCur)
	binary.BigEndian.PutUint64(tmp[16:], lenPrev)
	copy(tmp[24:], payloadHash)
	copy(tmp[24+lc.HashOutputLen:], headerHash)
	copy(tmp[24+2*lc.HashOutputLen:], rootHash)
	binary.BigEndian.PutUint64(tmp[24+3*lc.HashOutputLen:], time)
	copy(tmp[32+3*lc.HashOutputLen:], signature)
	copy(tmp[WireBlockHeaderSize:], payload)

	return tmp, nil
}

func packData(events [][]byte, policy Policy,
	encrypt, compress bool) (payload, payloadHash, rootHash []byte, err error) {
	// FIXME: measure if memory is an issue, look at createing a packData that can be streamed, and likely calculate payloadHash here as well then
	for i := 0; i < len(events); i++ {
		size := make([]byte, 2)
		if len(events[i]) > 65535 {
			return nil, nil, nil, fmt.Errorf("too large events, max %d, got %d",
				65535, len(events[i]))
		}
		binary.BigEndian.PutUint16(size, uint16(len(events[i])))
		payload = append(payload, size...)
		payload = append(payload, events[i]...)
	}

	iv := make([]byte, IVsize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, nil, nil, err
	}
	rootHash = lc.Khash(iv, MerkleTreeHash(events))
	payload = append(payload, iv...)

	if compress {
		payload, err = lc.Compress(payload)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if encrypt {
		payload, err = lc.Encrypt(policy.Pub, payload)
	}
	payloadHash = lc.Khash(policy.ID, payload)

	return
}

func DecodeBlockHeader(encoded []byte, policy Policy) (b BlockHeader, err error) {
	if len(encoded) < WireBlockHeaderSize {
		return BlockHeader{}, fmt.Errorf("too short data, expected at least %d, got %d",
			WireBlockHeaderSize, len(encoded))
	}
	// map encoded format to BlockHeader struct
	b.Index = binary.BigEndian.Uint64(encoded)
	b.LenCur = binary.BigEndian.Uint64(encoded[8:])
	b.LenPrev = binary.BigEndian.Uint64(encoded[16:])
	b.PayloadHash = make([]byte, lc.HashOutputLen)
	copy(b.PayloadHash, encoded[24:])
	b.HeaderHash = make([]byte, lc.HashOutputLen)
	copy(b.HeaderHash, encoded[24+lc.HashOutputLen:])
	b.RootHash = make([]byte, lc.HashOutputLen)
	copy(b.RootHash, encoded[24+2*lc.HashOutputLen:])
	b.Time = binary.BigEndian.Uint64(encoded[24+3*lc.HashOutputLen:])
	b.Signature = make([]byte, lc.SignatureSize)
	copy(b.Signature, encoded[32+3*lc.HashOutputLen:])

	// the fields of the block that should be signed
	signed := make([]byte, lc.HashOutputLen*2+8)
	copy(signed, b.HeaderHash)
	copy(signed[lc.HashOutputLen:], b.RootHash)
	binary.BigEndian.PutUint64(signed[lc.HashOutputLen*2:], b.Time)
	if !lc.Verify(policy.Vk, signed, b.Signature) {
		return BlockHeader{}, fmt.Errorf("invalid signature in block header")
	}

	// make sure we can trust provided fields and figure out payload to expect
	valid, encrypted, compressed := checkBlockHeaderHash(b, policy)
	if !valid {
		return BlockHeader{}, fmt.Errorf("invalid header hash")
	}
	b.Encrypted = encrypted
	b.Compressed = compressed

	return
}

func checkBlockHeaderHash(b BlockHeader, policy Policy) (valid, encrypted, compressed bool) {
	fn := func(buf []byte, enc, comp bool) bool {
		if enc {
			buf[3*8+lc.HashOutputLen] = WireTrue
		} else {
			buf[3*8+lc.HashOutputLen] = WireFalse
		}
		if comp {
			buf[3*8+lc.HashOutputLen+1] = WireTrue
		} else {
			buf[3*8+lc.HashOutputLen+1] = WireFalse
		}
		return subtle.ConstantTimeCompare(lc.Khash(policy.ID, buf), b.HeaderHash) == 1
	}
	tmp := make([]byte, 3*8+lc.HashOutputLen+2)
	binary.BigEndian.PutUint64(tmp, b.Index)
	binary.BigEndian.PutUint64(tmp[8:], b.LenCur)
	binary.BigEndian.PutUint64(tmp[16:], b.LenPrev)
	copy(tmp[24:], b.PayloadHash)
	switch {
	case fn(tmp, true, true): // encrypted and compressed?
		return true, true, true
	case fn(tmp, true, false): // encrypted but not compressed?
		return true, true, false
	case fn(tmp, false, true): // plaintext but compressed?
		return true, false, true
	case fn(tmp, false, false): // plaintext and not compressed?
		return true, false, false
	default:
		return false, false, false
	}
}

func DecodeBlockPayload(payload, pub, pk []byte, policy Policy, bh BlockHeader) (events [][]byte,
	IV []byte, err error) {
	if uint64(len(payload)) != bh.LenCur-WireBlockHeaderSize {
		return nil, nil, fmt.Errorf("invalid payload length, expected %d, got %d",
			bh.LenCur-WireBlockHeaderSize, len(payload))
	}
	if !CheckPayloadHash(payload, policy, bh) {
		return nil, nil, fmt.Errorf("invalid payload hash")
	}

	buf := payload
	if bh.Encrypted {
		buf, err = lc.Decrypt(buf, pub, pk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt: %s", err)
		}
	}
	if bh.Compressed {
		buf, err = lc.Decompress(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decompress: %s", err)
		}
	}
	IV = buf[len(buf)-IVsize:]

	buf = buf[:len(buf)-IVsize]
	for {
		if len(buf) == 0 {
			break
		}
		l := binary.BigEndian.Uint16(buf[:2]) // take out len
		buf = buf[2:]
		if l < 0 || int(l) > len(buf) {
			return nil, nil, fmt.Errorf("invalid encoded events")
		}
		events = append(events, buf[:l])
		buf = buf[l:]
	}

	return
}

func CheckPayloadHash(payload []byte, policy Policy, bh BlockHeader) bool {
	return subtle.ConstantTimeCompare(lc.Khash(policy.ID, payload), bh.PayloadHash) == 1
}
