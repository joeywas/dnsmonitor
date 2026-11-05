package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
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
	Name             string                    `yaml:"name"`
	Hostname         string                    `yaml:"hostname"`
	Interval         Duration                  `yaml:"interval"`
	Timeout          Duration                  `yaml:"timeout"`
	UDPRetries       int                       `yaml:"udp_retries"`
	EDNSUDPSize      uint16                    `yaml:"edns_udp_size"`
	RecursionDesired bool                      `yaml:"recursion_desired"`
	RecordTypes      []string                  `yaml:"record_types"`
	ExpectedAnswers  map[string]ExpectedAnswer `yaml:"expected_answers"`
}

type ExpectedAnswer struct {
	RCode   string   `yaml:"rcode"`
	Answers []string `yaml:"answers"`
}

func (expected *ExpectedAnswer) UnmarshalYAML(node *yaml.Node) error {
	var value struct {
		RCode   string    `yaml:"rcode"`
		Answers *[]string `yaml:"answers"`
	}
	if err := node.Decode(&value); err != nil {
		return err
	}
	if value.Answers == nil {
		return fmt.Errorf("expected answer entry must include answers; use [] to expect no records")
	}
	expected.RCode = value.RCode
	expected.Answers = *value.Answers
	return nil
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
		if err := validateExpectedAnswers(t); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

func validateExpectedAnswers(target *Target) error {
	if len(target.ExpectedAnswers) == 0 {
		return nil
	}
	configuredTypes := make(map[string]bool, len(target.RecordTypes))
	for _, recordType := range target.RecordTypes {
		configuredTypes[strings.ToUpper(recordType)] = true
	}

	normalized := make(map[string]ExpectedAnswer, len(target.ExpectedAnswers))
	for recordType, expected := range target.ExpectedAnswers {
		recordType = strings.ToUpper(recordType)
		qtype := dns.StringToType[recordType]
		if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeCNAME && qtype != dns.TypeTXT {
			return fmt.Errorf("target %q expected_answers supports only A, AAAA, CNAME, and TXT, got %q", target.Name, recordType)
		}
		if !configuredTypes[recordType] {
			return fmt.Errorf("target %q expected_answers configures %s but record_types does not", target.Name, recordType)
		}
		if _, exists := normalized[recordType]; exists {
			return fmt.Errorf("target %q has duplicate expected_answers entry for %s", target.Name, recordType)
		}

		if expected.RCode == "" {
			expected.RCode = "NOERROR"
		} else {
			rcode, ok := dns.StringToRcode[strings.ToUpper(expected.RCode)]
			if !ok {
				return fmt.Errorf("target %q expected_answers for %s has unsupported rcode %q", target.Name, recordType, expected.RCode)
			}
			expected.RCode = dns.RcodeToString[rcode]
		}

		for i, answer := range expected.Answers {
			normalizedAnswer, err := NormalizeExpectedAnswer(target.Hostname, qtype, answer)
			if err != nil {
				return fmt.Errorf("target %q expected_answers for %s: %w", target.Name, recordType, err)
			}
			expected.Answers[i] = normalizedAnswer
		}
		normalized[recordType] = expected
	}
	target.ExpectedAnswers = normalized
	return nil
}

func NormalizeExpectedAnswer(owner string, qtype uint16, value string) (string, error) {
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || qtype == dns.TypeA && ip.To4() == nil || qtype == dns.TypeAAAA && (ip.To16() == nil || ip.To4() != nil) {
			return "", fmt.Errorf("invalid %s address %q", dns.TypeToString[qtype], value)
		}
		if qtype == dns.TypeA {
			return ip.To4().String(), nil
		}
		return ip.String(), nil
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s 0 IN %s %s", dns.Fqdn(owner), dns.TypeToString[qtype], strings.TrimSpace(value)))
	if err != nil {
		return "", fmt.Errorf("invalid %s RDATA %q: %w", dns.TypeToString[qtype], value, err)
	}
	return NormalizeAnswerRR(rr)
}

func NormalizeAnswerRR(rr dns.RR) (string, error) {
	switch record := rr.(type) {
	case *dns.A:
		if record.A.To4() == nil {
			return "", fmt.Errorf("invalid A address")
		}
		return record.A.To4().String(), nil
	case *dns.AAAA:
		if record.AAAA.To16() == nil || record.AAAA.To4() != nil {
			return "", fmt.Errorf("invalid AAAA address")
		}
		return record.AAAA.String(), nil
	case *dns.CNAME:
		return strings.ToLower(dns.Fqdn(record.Target)), nil
	case *dns.TXT:
		data, err := json.Marshal(record.Txt)
		if err != nil {
			return "", err
		}
		return string(data), nil
	default:
		return "", fmt.Errorf("unsupported answer type %s", dns.TypeToString[rr.Header().Rrtype])
	}
}
