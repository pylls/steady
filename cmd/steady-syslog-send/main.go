package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"time"

	"github.com/montanaflynn/stats"
)

var (
	input     = flag.String("input", "events.log", "file with input data, each line read as an event")
	n         = flag.Int("n", 10, "number of repetitions")
	transport = flag.String("t", "udp", "transport")

	events     [][]byte
	eventsSize int64
	mean, std  float64
)

func main() {
	flag.Parse()
	events, eventsSize, mean, std = readEvents()
	log.Printf("read %d events from %s, total size %d KiB, mean %.2f±%.2f", len(events), *input, eventsSize, mean, std)

	sysLog, err := syslog.Dial(*transport, flag.Arg(0), syslog.LOG_WARNING|syslog.LOG_DAEMON, "bench")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("syslog send starting %d rounds", *n)
	duration := make([]time.Duration, *n)
	for round := 0; round < *n; round++ {
		start := time.Now()
		for i := 0; i < len(events); i++ {
			fmt.Fprintf(sysLog, string(events[i]))
		}
		duration[round] = time.Now().Sub(start)
		log.Printf("round %d took %s", round, duration[round])
	}

	csv := "exp,flush,time(s),events/s,goodput(KiB/s)\n"
	csv += cvslines(duration)
	fmt.Printf("%s", csv)
	log.Println("done")
}

func cvslines(durations []time.Duration) (r string) {
	for i := 0; i < len(durations); i++ {
		secDur := float64(durations[i]) / float64(time.Second)
		r += fmt.Sprintf("%s,1,%.2f,%.2f,%.2f\n", expname(),
			secDur,
			float64(len(events))/secDur,
			float64(eventsSize)/(secDur*1024))
	}
	return
}

func readEvents() (events [][]byte, totalSize int64, mean, std float64) {
	events = make([][]byte, 0)
	file, err := os.Open(*input)
	if err != nil {
		log.Fatalf("failed to read events from input: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	sizes := make([]float64, 0)
	for scanner.Scan() {
		e := []byte(scanner.Text())
		events = append(events, e)
		sizes = append(sizes, float64(len(e)))
		totalSize += int64(len(e))
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("failed to scan: %s", err)
	}
	std, _ = stats.StandardDeviationPopulation(sizes)
	mean, _ = stats.Mean(sizes)

	return
}

func expname() string {
	location := "local"
	if len(flag.Arg(0)) > 0 {
		location = flag.Arg(0)
	}

	return location + "-syslog"
}
