package main

import (
	"container/list"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net"

	"github.com/pylls/steady"
	"github.com/pylls/steady/lc"
)

func setup(conn net.Conn) {
	buf := make([]byte, steady.WirePolicySize+steady.WireAuthSize)
	l, err := conn.Read(buf)
	if err != nil {
		log.Printf("\tfailed to read policy: %v", err)
		return
	}
	if l != steady.WirePolicySize+steady.WireAuthSize {
		log.Printf("\tfailed to read policy, expected %d bytes, got %d",
			steady.WirePolicySize+steady.WireAuthSize, l)
		return
	}

	if subtle.ConstantTimeCompare(buf[steady.WirePolicySize:], // sent tag
		lc.Khash([]byte(*token), []byte("setup"), buf[:steady.WirePolicySize])) != 1 {
		log.Printf("\tinvalid auth for setup")
		return
	}

	p, err := steady.DecodePolicy(buf[:steady.WirePolicySize])
	if err != nil {
		log.Printf("\tfailed to decode policy: %v", err)
		return
	}
	lock.Lock()
	defer lock.Unlock()
	_, exists := state[hex.EncodeToString(p.ID)]
	if exists {
		log.Println("\tpolicy already exists")
		return
	}

	// TODO: add detailed setup checks
	state[hex.EncodeToString(p.ID)] = State{
		policy: p,
		blocks: list.New(),
	}
	log.Printf("\tcompleted, id: %s", hex.EncodeToString(p.ID))
}
