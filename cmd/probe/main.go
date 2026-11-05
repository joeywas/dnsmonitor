package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"dns-monitor/internal/config"
	"dns-monitor/internal/monitoring"
)

func main() {
	configPath := flag.String("config", "configs/targets.yaml", "configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	// Each DNS attempt has its own configured timeout. Avoid imposing a
	// shorter global deadline that could cancel a legitimate retry sequence.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results, err := monitoring.Run(ctx, cfg)
	if err != nil {
		log.Printf("probe completed with errors: %v", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		log.Fatal(err)
	}
}
