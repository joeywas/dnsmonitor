package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

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

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

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
