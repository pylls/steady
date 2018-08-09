package main

import (
	"flag"
	"log"
	"net"
	"sync"

	"github.com/pylls/steady"
)

var (
	state  map[string]State
	lock   sync.Mutex
	token  = flag.String("token", "secret", "the access token")
	listen = flag.String("listen", "0.0.0.0:22333", "the address to listen on")
)

func main() {
	flag.Parse()
	state = make(map[string]State)

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()
	log.Println("steady-server listening...")

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("error accepting connection: %v", err)
		}
		go handler(conn)
	}
}

func handler(conn net.Conn) {
	defer conn.Close()

	for {
		buf := make([]byte, 2)
		l, err := conn.Read(buf)
		if err != nil {
			log.Printf("failed to read: %v", err)
			return
		}
		if l < 2 {
			log.Println("failed to read command bytes")
			return
		}
		if buf[0] > steady.WireVersion {
			log.Println("got newer version of Steady")
			return
		}

		switch buf[1] {
		case steady.WireCmdWriteN: // auth on ACK
			log.Println("writeN cmd")
			writeN(conn)
		case steady.WireCmdWrite: // auth on ACK
			log.Println("write cmd")
			write(conn)
		case steady.WireCmdSetup: // auth on setup parameters
			log.Println("setup cmd")
			setup(conn)
		case steady.WireCmdRead: // public
			log.Println("read cmd")
			read(conn)
		case steady.WireCmdStatus: // public
			log.Println("status cmd")
			status(conn)
		default:
			log.Println("unknown command")
			return
		}
	}
}
