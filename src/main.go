package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4sni/sni"
)

func main() {
	extractor := &sni.SNIExtractor{
		TcpTracker: sni.NewTCPStreamTracker(),
	}

	if err := extractor.Init(); err != nil {
		log.Fatal(err)
	}
	defer extractor.Close()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Stats ticker
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()

	go func() {
		for range sigChan {
			fmt.Printf("\n\nShutting down...\n")
			extractor.Close()
			os.Exit(0)
		}
	}()

	extractor.Run()
}
