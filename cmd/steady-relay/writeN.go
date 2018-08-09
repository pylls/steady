package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/pylls/steady"
	"github.com/pylls/steady/lc"
)

/*
 * general idea of writeN:
 * - have device send n
 * - attempt to read n blocks, only store in the very end, error early
 * - fixed-size reply: error or auth the last block index
 */
func writeN(conn net.Conn) {
	// read id
	id, _, err := getID(conn)
	if err != nil {
		log.Printf("\tfailed to get id: %v", err)
		return
	}

	lock.Lock()
	defer lock.Unlock()
	// see if in state, reject if not
	s, exists := state[id]
	if !exists {
		log.Printf("\tno such state")
		return
	}

	// get N from client
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		log.Printf("\tfailed to read N: %v", err)
		return
	}
	N := binary.BigEndian.Uint16(buf)

	// attempt to buffer N blocks
	reply := make([]byte, 8+steady.WireAuthSize)
	for i := 0; i < len(reply); i++ {
		reply[i] = 0
	}
	blocks := make([]*Block, 0, N)
	for i := uint16(0); i < N; i++ {
		b, err := readBlock(conn, s.policy, s.nextIndex+uint64(i))
		if err != nil {
			conn.Write(reply) // send zero reply to indicate error
			log.Printf("\tfailed to read block (%v)", err)
			return
		}
		blocks = append(blocks, b)
	}

	// all OK, store blocks and update state
	for i := 0; i < len(blocks); i++ {
		s.space, s.nextIndex = store(blocks[i], s.blocks, s.space, s.policy)
	}
	state[id] = s

	// reply with index of successfully written block, authenticate with policy ID and token
	buf = make([]byte, 8+steady.WireAuthSize)
	binary.BigEndian.PutUint64(buf, blocks[len(blocks)-1].Header.Index)
	copy(buf[8:], lc.Khash([]byte(*token), []byte("writeN"), s.policy.ID, buf[:8]))
	conn.Write(buf)
	log.Printf("\twrote %d block(s)", N)
}

func readBlock(conn net.Conn, policy steady.Policy, expectedIndex uint64) (b *Block, err error) {
	// read header length
	encodedHeader := make([]byte, steady.WireBlockHeaderSize)
	l, err := io.ReadFull(conn, encodedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to read block header: %v", err)
	}
	if l != steady.WireBlockHeaderSize {
		return nil, fmt.Errorf("wrong block header size, expected %d, got %d", steady.WireBlockHeaderSize, l)
	}

	// decode header
	bh, err := steady.DecodeBlockHeader(encodedHeader, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to decode block header: %v", err)
	}
	if bh.Index != expectedIndex {
		return nil, fmt.Errorf("wrong block index, expected %d, got %d", expectedIndex, bh.Index)
	}
	if bh.LenCur > steady.MaxBlockSize {
		return nil, fmt.Errorf("too large block, max is %d, got %d", steady.MaxBlockSize, bh.LenCur)
	}
	if bh.LenCur > policy.Space {
		return nil, fmt.Errorf("block is larger than policy max space")
	}

	// read payload
	buf := make([]byte, bh.LenCur-steady.WireBlockHeaderSize)
	l, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read block payload: %v", err)
	}
	if uint64(l) != bh.LenCur-steady.WireBlockHeaderSize {
		return nil, fmt.Errorf("wrong block payload size, expected %d, got %d",
			bh.LenCur-steady.WireBlockHeaderSize, l)
	}
	// check hash of payload
	if !steady.CheckPayloadHash(buf, policy, bh) {
		return nil, fmt.Errorf("invalid payload hash")
	}

	return &Block{
		Header:        bh,
		HeaderEncoded: encodedHeader,
		Payload:       buf,
	}, nil
}
