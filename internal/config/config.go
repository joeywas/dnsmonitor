package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type File struct {
	Targets []Target `yaml:"targets"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

type Target struct {
	Name             string   `yaml:"name"`
	Hostname         string   `yaml:"hostname"`
	Interval         Duration `yaml:"interval"`
	Timeout          Duration `yaml:"timeout"`
	UDPRetries       int      `yaml:"udp_retries"`
	EDNSUDPSize      uint16   `yaml:"edns_udp_size"`
	RecursionDesired bool     `yaml:"recursion_desired"`
	RecordTypes      []string `yaml:"record_types"`
}

func Load(path string) (File, error) {
	var cfg File
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if len(cfg.Targets) == 0 {
		return cfg, fmt.Errorf("configuration contains no targets")
	}
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if t.Hostname == "" {
			return cfg, fmt.Errorf("target %q has no hostname", t.Name)
		}
		if t.Timeout <= 0 {
			t.Timeout = Duration(2 * time.Second)
		}
		if t.UDPRetries < 0 || t.UDPRetries > 2 {
			return cfg, fmt.Errorf("target %q udp_retries must be between 0 and 2", t.Name)
		}
		if t.EDNSUDPSize == 0 {
			t.EDNSUDPSize = 1232
		}
		if len(t.RecordTypes) == 0 {
			t.RecordTypes = []string{"SOA", "NS", "A", "AAAA"}
		}
	}
	return cfg, nil
}
