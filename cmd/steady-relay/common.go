package main

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/pylls/steady"
)

func getID(conn net.Conn) (string, []byte, error) {
	buf := make([]byte, steady.WireIdentifierSize)
	if err := readn(buf, steady.WireIdentifierSize, conn); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(buf), buf, nil
}

func readn(dst []byte, n int, conn net.Conn) error {
	l, err := conn.Read(dst)
	if err != nil {
		return fmt.Errorf("failed to read from conn: %v", err)
	}
	if l < n {
		return fmt.Errorf("read %d bytes from conn, expected %d", l, n)
	}
	return nil
}
