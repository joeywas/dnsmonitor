package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExpectedAnswers(t *testing.T) {
	path := writeConfig(t, `targets:
  - name: test
    hostname: example.test
    record_types: [A, AAAA]
    expected_answers:
      A:
        rcode: noerror
        answers: [192.0.2.10]
      AAAA:
        answers: []
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Targets[0].ExpectedAnswers["A"]; got.RCode != "NOERROR" || len(got.Answers) != 1 || got.Answers[0] != "192.0.2.10" {
		t.Fatalf("unexpected A expectation: %#v", got)
	}
	if got := cfg.Targets[0].ExpectedAnswers["AAAA"]; got.RCode != "NOERROR" || len(got.Answers) != 0 {
		t.Fatalf("unexpected AAAA expectation: %#v", got)
	}
}

func TestLoadRejectsExpectedAnswerTypeNotQueried(t *testing.T) {
	path := writeConfig(t, `targets:
  - name: test
    hostname: example.test
    record_types: [A]
    expected_answers:
      AAAA:
        answers: []
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "record_types") {
		t.Fatalf("expected record_types validation error, got %v", err)
	}
}

func TestLoadRejectsInvalidExpectedIP(t *testing.T) {
	path := writeConfig(t, `targets:
  - name: test
    hostname: example.test
    record_types: [A]
    expected_answers:
      A:
        answers: [2001:db8::1]
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "invalid A address") {
		t.Fatalf("expected invalid IP validation error, got %v", err)
	}
}

func TestLoadRejectsExpectedAnswerWithoutAnswers(t *testing.T) {
	path := writeConfig(t, `targets:
  - name: test
    hostname: example.test
    record_types: [A]
    expected_answers:
      A:
        rcode: NOERROR
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "must include answers") {
		t.Fatalf("expected missing answers validation error, got %v", err)
	}
}

func TestLoadExpectedCNAMEAndTXTAnswers(t *testing.T) {
	path := writeConfig(t, `targets:
  - name: test
    hostname: example.test
    record_types: [CNAME, TXT]
    expected_answers:
      CNAME:
        answers: [Target.Example.Test]
      TXT:
        answers: ['"v=spf1 -all"']
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := cfg.Targets[0].ExpectedAnswers
	if got := expected["CNAME"].Answers[0]; got != "target.example.test." {
		t.Errorf("CNAME answer=%q, want target.example.test.", got)
	}
	if got := expected["TXT"].Answers[0]; got != `["v=spf1 -all"]` {
		t.Errorf("TXT answer=%q, want canonical TXT value", got)
	}
}

func TestRepositoryTargetConfigLoadsVerifiedAnswer(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "targets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	target := cfg.Targets[0]
	if got := target.ExpectedAnswers["A"].Answers; len(got) != 1 || got[0] != "159.121.71.106" {
		t.Fatalf("configured A answers=%v, want [159.121.71.106]", got)
	}
	configuredTypes := map[string]bool{}
	for _, configuredTarget := range cfg.Targets {
		for _, recordType := range configuredTarget.RecordTypes {
			configuredTypes[strings.ToUpper(recordType)] = true
		}
	}
	if !configuredTypes["CNAME"] {
		t.Error("no target config enables CNAME queries")
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
