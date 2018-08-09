package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/fatih/color"
	"github.com/pylls/steady"
	"github.com/pylls/steady/collector"
	"github.com/tidwall/pretty"
)

var (
	path            = flag.String("path", "test", "the path")
	server          = flag.String("server", "localhost:22333", "the server")
	freq            = flag.Int("freq", 5, "poll frequency")
	delta           = flag.Uint64("delta", 30, "the maximum amount of drift (s) to accept")
	printAssessment = flag.Bool("assessments", false, "print collector assessments")
	printMsgs       = flag.Bool("messages", false, "print log messages")
	printSummary    = flag.Bool("summary", true, "print summary")
)

func main() {
	flag.Parse()

	// read collector config
	cc, err := collector.ReadCollectorConfig(fmt.Sprintf(steady.CollectorFilename, *path))
	if err != nil {
		log.Fatalf("failed to read collector config: %v", err)
	}
	log.Printf("read collector config at %s", fmt.Sprintf(steady.CollectorFilename, *path))

	c, err := collector.NewCollector(*server, *cc, time.Duration(*freq)*time.Second, *delta)
	if err != nil {
		log.Fatalf("failed to connect to relay: %s", err)
	}
	log.Printf("connected to relay at %s", *server)
	defer c.Close()

	log.Println("active policy")
	fmt.Printf("\t\t\t device ID:\t %s\n", hex.EncodeToString(cc.Policy.ID))
	fmt.Printf("\t\t\t creation time:\t %d\n", cc.Policy.Time)
	fmt.Printf("\t\t\t timeout (s):\t %d\n", cc.Policy.Timeout)
	fmt.Printf("\t\t\t space (KiB):\t %d\n", cc.Policy.Space/1024)

	log.Printf("polling relay every %ds, accepting a time drift of %ds", *freq, *delta)

	// verified, unverified, invalid, duplicate
	// blocks counter
	var numBlocksVerified, numBlocksBroken, numBlocksMissed, numEventsVerified, numEventsBroken int

	c.CollectLoop(collector.State{
		Index: 0,
		Time:  cc.Policy.Time,
	}, make(chan struct{}),
		func(label string, meta interface{}, format string, args ...interface{}) {
			switch label {
			case "verified":
				numEventsVerified++
				if *printMsgs {
					log.Printf("%s %s [%s ...]",
						color.GreenString("Message:"), fmt.Sprintf(format, args...),
						color.MagentaString("Proof:"))
				}
			// all the same from our PoV, should always be zero or bug
			case "unverified":
				numEventsBroken++
				if *printMsgs {
					log.Printf("%s %s", color.RedString("Unverified message:"), fmt.Sprintf(format, args...))
				}
			case "invalid":
				numEventsBroken++
				if *printMsgs {
					log.Printf("%s %s", color.RedString("Invalid message:"), fmt.Sprintf(format, args...))
				}
			case "duplicate":
				numEventsBroken++
				if *printMsgs {
					log.Printf("%s %s", color.RedString("Duplicate message:"), fmt.Sprintf(format, args...))
				}

			case "assessment":
				a := meta.(*collector.Assessment)
				numBlocksVerified += int(a.ValidBlocks)
				numBlocksBroken += int(a.DuplicateBlocks + a.InvalidBlocks)
				numBlocksMissed += int(a.MissedBlocks)

				if *printAssessment {
					m, err := json.Marshal(meta)
					if err != nil {
						log.Printf("failed to marshal meta: %s", err)
						return
					}
					log.Printf("%s: %s", label, fmt.Sprintf(format, args...))
					fmt.Print(string(pretty.Color(pretty.Pretty(m), nil)))
				}

				if *printSummary {
					var ass string
					switch a.Overall {
					case "ok":
						ass = color.GreenString(a.Overall)
					case "warning":
						ass = color.YellowString(a.Overall)
					case "evil":
						ass = color.RedString(a.Overall)
					default:
						ass = a.Overall
					}
					log.Printf("%s\t assessment: %17s\t\t events: %s verified, %s broken\t\t blocks: %s verified, %s missed, %s broken",
						color.CyanString("Summary"), ass,
						color.GreenString("%9d", numEventsVerified), color.RedString("%2d", numEventsBroken),
						color.GreenString("%4d", numBlocksVerified), color.YellowString("%4d", numBlocksMissed),
						color.RedString("%4d", numBlocksBroken))
				}
			}

			if meta == nil {
				log.Printf("%s: %s", label, fmt.Sprintf(format, args...))
			}
		})
}
