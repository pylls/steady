package main

import (
	"bufio"
	"flag"
	"log"
	"os"

	"github.com/pylls/steady/device"
)

var (
	timeout        = flag.Uint("timeout", 10, "the timeout")
	space          = flag.Uint("space", 100*1024, "the space")
	path           = flag.String("path", "test", "the path")
	token          = flag.String("token", "secret", "the access token")
	server         = flag.String("server", "localhost:22333", "the server")
	encrypt        = flag.Bool("encrypt", true, "use encryption")
	compress       = flag.Bool("compress", true, "use compression")
	flushSize      = flag.Int("flush", 1024, "buffer size in KiB")
	blockBufferNum = flag.Int("blocks", 5, "max number of blocks in buffer")
)

func main() {
	flag.Parse()

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		log.Fatalf("expect data over stdin to log, exit before loading device")
	}

	log.Printf("attempting to load device at %s...", *path)
	device, err := device.LoadDevice(*path, *server, *token,
		*encrypt, *compress, *flushSize*1024, *blockBufferNum)
	if err != nil {
		log.Fatalf("failed to load device: %v", err)
	}

	log.Println("ok, starting to read from stdin...")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if err = device.Log(scanner.Text()); err != nil {
			log.Fatalf("failed to log: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("failed to read from stdin: %v", err)
	}

	log.Println("all done, closing")
	device.Close()
}
