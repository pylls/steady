package main

import (
	"container/list"

	"github.com/pylls/steady"
)

type State struct {
	policy           steady.Policy
	blocks           *list.List
	space, nextIndex uint64
}

type Block struct {
	Header        steady.BlockHeader
	HeaderEncoded []byte
	Payload       []byte
}
