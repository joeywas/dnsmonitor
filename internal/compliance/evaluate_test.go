package compliance

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAssessTruncation(t *testing.T) {
	first := mustRR(t, "example.test. 300 IN A 192.0.2.1")
	second := mustRR(t, "example.test. 300 IN A 192.0.2.2")
	optional := mustRR(t, "ns.example.test. 300 IN A 192.0.2.53")

	tests := []struct {
		name       string
		udp        *dns.Msg
		tcp        *dns.Msg
		wantStatus string
	}{
		{
			name:       "TC for incomplete required RRset",
			udp:        responseWith([]dns.RR{first}, nil, nil, true),
			tcp:        responseWith([]dns.RR{first, second}, nil, nil, false),
			wantStatus: "PASS",
		},
		{
			name:       "TC only for omitted optional additional data",
			udp:        responseWith([]dns.RR{first, second}, nil, nil, true),
			tcp:        responseWith([]dns.RR{first, second}, nil, []dns.RR{optional}, false),
			wantStatus: "FAIL",
		},
		{
			name:       "missing required RRset without TC",
			udp:        responseWith([]dns.RR{first}, nil, nil, false),
			tcp:        responseWith([]dns.RR{first, second}, nil, nil, false),
			wantStatus: "FAIL",
		},
		{
			name:       "complete required RRset without TC despite optional omission",
			udp:        responseWith([]dns.RR{first, second}, nil, nil, false),
			tcp:        responseWith([]dns.RR{first, second}, nil, []dns.RR{optional}, false),
			wantStatus: "PASS",
		},
		{
			name:       "unstable required RRsets",
			udp:        responseWith([]dns.RR{first}, nil, nil, true),
			tcp:        responseWith([]dns.RR{second}, nil, nil, false),
			wantStatus: "INCONCLUSIVE",
		},
		{
			name:       "UDP-only required data is inconclusive",
			udp:        responseWith([]dns.RR{first, second}, nil, nil, false),
			tcp:        responseWith([]dns.RR{first}, nil, nil, false),
			wantStatus: "INCONCLUSIVE",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := AssessTruncation(test.udp, test.tcp)
			if finding.Status != test.wantStatus {
				t.Fatalf("status=%s, want %s: %s", finding.Status, test.wantStatus, finding.Detail)
			}
			if finding.Standard != "RFC 2181 Section 9" {
				t.Errorf("standard=%q, want RFC 2181 Section 9", finding.Standard)
			}
		})
	}
}

func responseWith(answer, authority, additional []dns.RR, truncated bool) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = answer
	response.Ns = authority
	response.Extra = additional
	response.Truncated = truncated
	return response
}

func mustRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
