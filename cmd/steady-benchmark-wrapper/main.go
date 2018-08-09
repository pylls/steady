package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os/exec"
	"strconv"
	"time"
)

var (
	logFile = flag.String("log", "darthdone.log", "the file with logdata")
	relay   = flag.String("server", "127.0.0.1", "location of relay")
	n       = flag.Int("n", 4, "number of repetitions")
	minMem  = flag.Int("mmin", 3, "min device memory limit (2^min) MiB")
	maxMem  = flag.Int("mmax", 10, "max device memory limit (2^max) MiB")
)

func main() {
	flag.Parse()

	// read in entire log file into memory, one large blob is likely best (?)
	dataset, err := ioutil.ReadFile(*logFile)
	if err != nil {
		log.Fatalf("failed to read log file: %v", err)
	}
	numEvents := countEvents(dataset)
	log.Printf("successfully read log data from %s (%d events and %.2f KiB)",
		*logFile, numEvents, float64(len(dataset))/1024.0)

	csv := "exp,memory(MiB),time(s),events/s,goodput(KiB/s)\n"
	for encrypt := 0; encrypt < 2; encrypt++ {
		for compress := 0; compress < 2; compress++ {
			for memory := int(math.Pow(2, float64(*minMem))); memory <= int(math.Pow(2, float64(*maxMem))); memory *= 2 {
				for i := 0; i < *n; i++ {
					log.Printf("memory %6d: starting run %d/%d", memory, i+1, *n)
					duration := run(dataset, memory, encrypt, compress)
					csv += csvline(expname(*relay, encrypt, compress),
						memory, duration, numEvents, len(dataset))
					time.Sleep(2 * time.Second)
				}

			}
		}
	}
	fmt.Printf("%s", csv)
	log.Printf("done")
}

func expname(loc string, encrypt, compress int) string {
	if encrypt == 1 && compress == 1 {
		return loc + "-enc-comp"
	}
	if encrypt == 1 {
		return loc + "-enc"
	}
	if compress == 1 {
		return loc + "-comp"
	}
	return loc + "-plain"
}

func csvline(exp string, memory int, duration time.Duration, n, size int) string {
	secDuration := float64(duration) / float64(time.Second)
	return fmt.Sprintf("%s,%d,%.2f,%.2f,%.2f\n",
		exp, memory, secDuration, float64(n)/secDuration, float64(size)/(secDuration*1024))
}

func countEvents(dataset []byte) (numEvents int) {
	scanner := bufio.NewScanner(bytes.NewReader(dataset))
	for scanner.Scan() {
		numEvents++
	}

	return
}

func run(dataset []byte, memory, encrypt, compress int) time.Duration {
	// launch device
	cmd := exec.Command("./demo",
		*relay, strconv.Itoa(memory), strconv.Itoa(encrypt), strconv.Itoa(compress))
	in, err := cmd.StdinPipe()
	if err != nil {
		log.Fatalf("failed to get stdin pipe: %v", err)
	}
	if err = cmd.Start(); err != nil {
		log.Fatalf("failed to start: %v", err)
	}
	// wait one second for connecting
	time.Sleep(1 * time.Second)

	start := time.Now()
	if _, err := in.Write(dataset); err != nil {
		log.Fatalf("failed to write dataset to stdin: %v", err)
	}
	if err = in.Close(); err != nil {
		log.Fatalf("failed to close stdin: %v", err)
	}
	if err = cmd.Wait(); err != nil {
		log.Fatalf("failed to wait for cmd to stop: %v", err)
	}
	return time.Now().Sub(start)
}
