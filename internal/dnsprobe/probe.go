package dnsprobe

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type Attempt struct {
	Transport  string    `json:"transport"`
	Attempt    int       `json:"attempt"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS float64   `json:"duration_ms"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	Rcode      string    `json:"rcode,omitempty"`
	AA         bool      `json:"aa,omitempty"`
	TC         bool      `json:"tc,omitempty"`
	RA         bool      `json:"ra,omitempty"`
	Answers    int       `json:"answers,omitempty"`
	Authority  int       `json:"authority,omitempty"`
	Additional int       `json:"additional,omitempty"`
}

func Query(ctx context.Context, server, qname string, qtype uint16, transport string, timeout time.Duration, ednsSize uint16, rd bool, attempt int) (Attempt, *dns.Msg) {
	result := Attempt{Transport: transport, Attempt: attempt, StartedAt: time.Now().UTC()}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	msg.RecursionDesired = rd
	if ednsSize > 0 {
		msg.SetEdns0(ednsSize, false)
	}

	client := &dns.Client{Net: transport, Timeout: timeout}
	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	result.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	if resp == nil {
		result.Error = "empty DNS response"
		return result, nil
	}
	result.Success = true
	result.Rcode = dns.RcodeToString[resp.Rcode]
	result.AA, result.TC, result.RA = resp.Authoritative, resp.Truncated, resp.RecursionAvailable
	result.Answers, result.Authority, result.Additional = len(resp.Answer), len(resp.Ns), len(resp.Extra)
	return result, resp
}

func ValidateResponse(query, response *dns.Msg, expectAA bool) error {
	if response == nil {
		return fmt.Errorf("no response")
	}
	if response.Id != query.Id {
		return fmt.Errorf("transaction ID mismatch")
	}
	if response.Response == false {
		return fmt.Errorf("QR response bit is not set")
	}
	if len(response.Question) != 1 {
		return fmt.Errorf("unexpected question count: %d", len(response.Question))
	}
	if response.Question[0].Name != query.Question[0].Name || response.Question[0].Qtype != query.Question[0].Qtype {
		return fmt.Errorf("question section does not match query")
	}
	if expectAA && !response.Authoritative {
		return fmt.Errorf("expected authoritative answer (AA=1)")
	}
	return nil
}
