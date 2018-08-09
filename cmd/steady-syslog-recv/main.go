package main

import (
	"flag"
	"fmt"
	"log"

	syslog "gopkg.in/mcuadros/go-syslog.v2"
)

var (
	mod  = flag.Int("mod", 1000*1000, "how often to print count to stdout")
	port = flag.Int("p", 514, "port to listen on")
)

func main() {
	flag.Parse()

	server := syslog.NewServer()
	channel := make(syslog.LogPartsChannel, 1024)
	handler := syslog.NewChannelHandler(channel)
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)

	if err := server.ListenUDP(fmt.Sprintf(":%d", *port)); err != nil {
		log.Fatalf("syslog server failed to listen for UDP: %s", err)
	}
	if err := server.ListenTCP(fmt.Sprintf(":%d", *port)); err != nil {
		log.Fatalf("syslog server failed to listen for TCP: %s", err)
	}
	if err := server.Boot(); err != nil {
		log.Fatalf("syslog server failed to boot: %s", err)
	}

	go func(channel syslog.LogPartsChannel) {
		n := 0
		for range channel {
			n++
			if n%*mod == 0 {
				log.Printf("received %d events", n)
			}
		}
	}(channel)

	log.Printf("syslog receive up and running on port %d", *port)
	server.Wait()
}
