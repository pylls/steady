package main

import (
	"container/list"
	"encoding/binary"
	"io"
	"log"
	"net"

	"github.com/pylls/steady"
	"github.com/pylls/steady/lc"
)

func write(conn net.Conn) {
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

	// read header length
	encodedHeader := make([]byte, steady.WireBlockHeaderSize)
	l, err := io.ReadFull(conn, encodedHeader)
	if err != nil {
		log.Printf("\tfailed to read block header: %v", err)
		return
	}
	if l != steady.WireBlockHeaderSize {
		log.Printf("\twrong block header size, expected %d, got %d", steady.WireBlockHeaderSize, l)
		return
	}

	// decode header
	bh, err := steady.DecodeBlockHeader(encodedHeader, s.policy)
	if err != nil {
		log.Printf("\tfailed to decode block header: %v", err)
		return
	}
	if bh.Index != s.nextIndex {
		log.Printf("\twrong block index, expected %d, got %d", s.nextIndex, bh.Index)
		return
	}
	if bh.LenCur > steady.MaxBlockSize {
		log.Printf("\ttoo large block, max is %d, got %d",
			steady.MaxBlockSize, bh.LenCur)
		return
	}
	if bh.LenCur > s.policy.Space {
		log.Printf("\tblock is larger than policy max space")
		return
	}

	buf := make([]byte, bh.LenCur-steady.WireBlockHeaderSize)
	l, err = io.ReadFull(conn, buf)
	//l, err = conn.Read(buf)
	if err != nil {
		log.Printf("\tfailed to read block payload: %v", err)
		return
	}
	if uint64(l) != bh.LenCur-steady.WireBlockHeaderSize {
		log.Printf("\twrong block payload size, expected %d, got %d",
			bh.LenCur-steady.WireBlockHeaderSize, l)
		return
	}
	log.Println("\tgot new block...")
	// check hash of payload
	if !steady.CheckPayloadHash(buf, s.policy, bh) {
		log.Println("\tinvalid payload hash")
		return
	}

	// store block and update state
	s.space, s.nextIndex = store(&Block{
		Header:        bh,
		HeaderEncoded: encodedHeader,
		Payload:       buf,
	}, s.blocks, s.space, s.policy)
	state[id] = s

	// reply with index of successfully written block, authenticate with policy ID and token
	buf = make([]byte, 8+steady.WireAuthSize)
	binary.BigEndian.PutUint64(buf, bh.Index)
	copy(buf[8:], lc.Khash([]byte(*token), []byte("write"), s.policy.ID, buf[:8]))
	conn.Write(buf)
	log.Println("\tand wrote new block")
}

func store(b *Block, blocks *list.List, space uint64, policy steady.Policy) (uint64, uint64) {
	blocks.PushBack(b)
	space += b.Header.LenCur

	// remove the front of the list and reduce current size until below max
	for space > policy.Space {
		log.Printf("\tremoved old block to make room...")
		space -= blocks.Remove(blocks.Front()).(*Block).Header.LenCur
	}

	return space, b.Header.Index + 1
}
