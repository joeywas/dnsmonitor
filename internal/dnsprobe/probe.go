package dnsprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Attempt struct {
	Transport         string    `json:"transport"`
	Server            string    `json:"server,omitempty"`
	Attempt           int       `json:"attempt"`
	StartedAt         time.Time `json:"started_at"`
	DurationMS        float64   `json:"duration_ms"`
	Received          bool      `json:"received"`
	Success           bool      `json:"success"`
	Outcome           string    `json:"outcome"`
	Error             string    `json:"error,omitempty"`
	ValidationError   string    `json:"validation_error,omitempty"`
	Rcode             string    `json:"rcode,omitempty"`
	AA                bool      `json:"aa"`
	TC                bool      `json:"tc"`
	RA                bool      `json:"ra"`
	Answers           int       `json:"answers"`
	AnswerRecords     []string  `json:"answer_records,omitempty"`
	Authority         int       `json:"authority"`
	AuthorityRecords  []string  `json:"authority_records,omitempty"`
	Additional        int       `json:"additional"`
	AdditionalRecords []string  `json:"additional_records,omitempty"`
}

type SOAData struct {
	Owner   string `json:"owner"`
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// Query sends one DNS query. Received means a DNS message arrived; Success means
// that it passed protocol/question validation and was authoritative as expected.
// RCODEs such as NXDOMAIN are still valid DNS responses and therefore Success.
func Query(ctx context.Context, server, qname string, qtype uint16, transport string, timeout time.Duration, ednsSize uint16, rd bool, attempt int) (Attempt, *dns.Msg, *dns.Msg) {
	result := Attempt{Transport: transport, Server: server, Attempt: attempt, StartedAt: time.Now().UTC()}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(qname), qtype)
	query.RecursionDesired = rd
	if ednsSize > 0 {
		query.SetEdns0(ednsSize, false)
	}

	client := &dns.Client{Net: transport, Timeout: timeout}
	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, query, server)
	result.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		result.Outcome = classifyExchangeError(ctx, err)
		result.Error = err.Error()
		return result, query, nil
	}
	if resp == nil {
		result.Outcome = "EMPTY_RESPONSE"
		result.Error = "empty DNS response"
		return result, query, nil
	}

	result.Received = true
	result.Rcode = dns.RcodeToString[resp.Rcode]
	if result.Rcode == "" {
		result.Rcode = fmt.Sprintf("RCODE_%d", resp.Rcode)
	}
	result.AA, result.TC, result.RA = resp.Authoritative, resp.Truncated, resp.RecursionAvailable
	result.Answers, result.Authority, result.Additional = len(resp.Answer), len(resp.Ns), len(resp.Extra)
	result.AnswerRecords = answerRRStrings(resp.Answer)
	result.AuthorityRecords = answerRRStrings(resp.Ns)
	result.AdditionalRecords = answerRRStrings(resp.Extra)

	if err := ValidateResponse(query, resp, true); err != nil {
		result.Outcome = "INVALID_RESPONSE"
		result.ValidationError = err.Error()
		return result, query, resp
	}
	result.Success = true
	result.Outcome = classifyResponse(resp)
	return result, query, resp
}

func answerRRStrings(records []dns.RR) []string {
	answers := make([]string, 0, len(records))
	for _, record := range records {
		answers = append(answers, record.String())
	}
	return answers
}

func classifyResponse(response *dns.Msg) string {
	if response.Truncated {
		return "TRUNCATED"
	}
	switch response.Rcode {
	case dns.RcodeSuccess:
		return "DNS_NOERROR"
	case dns.RcodeNameError:
		return "DNS_NXDOMAIN"
	case dns.RcodeRefused:
		return "DNS_REFUSED"
	case dns.RcodeServerFailure:
		return "DNS_SERVFAIL"
	default:
		return "DNS_OTHER_RCODE"
	}
}

func classifyExchangeError(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "CANCELED"
	}
	var networkError net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &networkError) && networkError.Timeout() {
		return "TIMEOUT"
	}
	return "TRANSPORT_ERROR"
}

func ValidateResponse(query, response *dns.Msg, expectAA bool) error {
	if query == nil {
		return fmt.Errorf("original query is nil")
	}
	if response == nil {
		return fmt.Errorf("no response")
	}
	if response.Id != query.Id {
		return fmt.Errorf("transaction ID mismatch: sent %d, received %d", query.Id, response.Id)
	}
	if !response.Response {
		return fmt.Errorf("QR response bit is not set")
	}
	if response.Opcode != query.Opcode {
		return fmt.Errorf("opcode mismatch: sent %d, received %d", query.Opcode, response.Opcode)
	}
	if len(query.Question) != 1 {
		return fmt.Errorf("original query has unexpected question count: %d", len(query.Question))
	}
	if len(response.Question) != 1 {
		return fmt.Errorf("response has unexpected question count: %d", len(response.Question))
	}
	q, got := query.Question[0], response.Question[0]
	if !strings.EqualFold(dns.Fqdn(got.Name), dns.Fqdn(q.Name)) || got.Qtype != q.Qtype || got.Qclass != q.Qclass {
		return fmt.Errorf("question mismatch: sent %s %s %s; received %s %s %s",
			q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype],
			got.Name, dns.ClassToString[got.Qclass], dns.TypeToString[got.Qtype])
	}
	if expectAA && !response.Authoritative {
		return fmt.Errorf("expected authoritative response (AA=1) for in-zone query")
	}
	return nil
}

func ExtractSOA(msg *dns.Msg) *SOAData {
	if msg == nil {
		return nil
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if soa, ok := rr.(*dns.SOA); ok {
				return &SOAData{
					Owner: dns.Fqdn(soa.Hdr.Name), MName: dns.Fqdn(soa.Ns), RName: dns.Fqdn(soa.Mbox),
					Serial: soa.Serial, Refresh: soa.Refresh, Retry: soa.Retry,
					Expire: soa.Expire, Minimum: soa.Minttl,
				}
			}
		}
	}
	return nil
}
