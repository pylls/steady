package main

import (
	"crypto/subtle"
	"log"
	"net"

	"github.com/pylls/steady"
	"github.com/pylls/steady/lc"
)

func status(conn net.Conn) {
	id, raw, err := getID(conn)
	if err != nil {
		log.Printf("\tfailed to get id: %v", err)
		return
	}
	log.Printf("\tid: %s", id)

	buf := make([]byte, steady.WireAuthSize)
	if err := readn(buf, steady.WireAuthSize, conn); err != nil {
		log.Printf("\tfailed to read auth token: %v", err)
		return
	}
	if subtle.ConstantTimeCompare(buf, lc.Khash([]byte(*token), []byte("status"), raw)) != 1 {
		log.Println("\tinvalid auth token")
		conn.Write([]byte{steady.WireAuthErr})
		return
	}

	lock.Lock()
	defer lock.Unlock()
	s, exists := state[id]
	if exists {
		if s.blocks.Len() == 0 {
			conn.Write([]byte{steady.WireTrue})
		} else {
			// reply with the latest block header
			conn.Write([]byte{steady.WireMore})
			conn.Write(s.blocks.Back().Value.(*Block).HeaderEncoded)
		}

	} else {
		conn.Write([]byte{steady.WireFalse})
	}
}
