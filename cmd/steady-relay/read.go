package main

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/pylls/steady"
	"github.com/pylls/steady/lc"
)

func read(conn net.Conn) {
	// read setup id
	id, _, err := getID(conn)
	if err != nil {
		log.Printf("\tfailed to get id: %v", err)
		return
	}

	// see if in state, reject if not
	lock.Lock()
	defer lock.Unlock()
	s, exists := state[id]
	if !exists {
		log.Printf("\tno such state")
		return
	}

	// read last read block index
	buf := make([]byte, 8)
	l, err := conn.Read(buf)
	if err != nil {
		log.Printf("failed to read block index: %v", err)
		return
	}
	if l != 8 {
		log.Printf("unexpected reply, expected %d, got %d", 8, l)
		return
	}
	index := binary.BigEndian.Uint64(buf)

	// first count the number of blocks and write
	var count uint64 = 0
	for e := s.blocks.Back(); e != nil; e = e.Prev() {
		if e.Value.(*Block).Header.Index >= index {
			count++
		} else {
			break // we know all blocks before also have a smaller index
		}
	}
	binary.BigEndian.PutUint64(buf, count)
	conn.Write(buf)

	// send each block
	for e := s.blocks.Back(); e != nil; e = e.Prev() { // traverse in reverse order
		block := e.Value.(*Block) // only cast once
		if block.Header.Index >= index {
			tmp := make([]byte, steady.WireBlockHeaderSize)
			binary.BigEndian.PutUint64(tmp, block.Header.Index)
			binary.BigEndian.PutUint64(tmp[8:], block.Header.LenCur)
			binary.BigEndian.PutUint64(tmp[16:], block.Header.LenPrev)
			copy(tmp[24:], block.Header.PayloadHash)
			copy(tmp[24+lc.HashOutputLen:], block.Header.HeaderHash)
			copy(tmp[24+2*lc.HashOutputLen:], block.Header.RootHash)
			binary.BigEndian.PutUint64(tmp[24+3*lc.HashOutputLen:], block.Header.Time)
			copy(tmp[32+3*lc.HashOutputLen:], block.Header.Signature)
			conn.Write(tmp)
			conn.Write(block.Payload)
		} else {
			break // we know all blocks before also have a smaller index
		}
	}
}
