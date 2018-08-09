package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/pylls/steady"
	"github.com/pylls/steady/collector"
	"github.com/pylls/steady/device"
	"github.com/pylls/steady/lc"
)

var (
	timeout = flag.Uint("timeout", 10, "the timeout")
	space   = flag.Uint("space", 100*1024*1024, "the space") // 100 MiB relay
	path    = flag.String("path", "test", "the path")
	token   = flag.String("token", "secret", "the access token")
	server  = flag.String("server", "localhost:22333", "the server")
)

func main() {
	flag.Parse()
	vk, sk, err := lc.SigningKeyGen()
	if err != nil {
		log.Fatalf("failed to generate signing keys: %v", err)
	}
	pub, priv, err := lc.EncryptKeyGen()
	if err != nil {
		log.Fatalf("failed to generate encryption keys: %v", err)
	}
	policy, err := device.MakeDevice(sk, vk, pub, uint64(*timeout), uint64(*space),
		uint64(time.Now().Unix()), *path, *server, *token)
	if err != nil {
		log.Fatalf("failed to make device: %v", err)
	}

	if err := collector.WriteCollectorConfig(&collector.Config{
		Pub:    pub,
		Priv:   priv,
		Vk:     vk,
		Policy: *policy,
	}, fmt.Sprintf(steady.CollectorFilename, *path)); err != nil {
		log.Fatalf("failed to write collector config: %v", err)
	}

	log.Printf("new device created, saved to %s", *path)
}
