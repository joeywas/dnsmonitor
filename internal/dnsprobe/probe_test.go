package dnsprobe

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func validPair() (*dns.Msg, *dns.Msg) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeSOA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Authoritative = true
	return q, r
}

func TestValidateResponseAcceptsMatchingAuthoritativeResponse(t *testing.T) {
	q, r := validPair()
	if err := ValidateResponse(q, r, true); err != nil {
		t.Fatalf("expected valid response, got %v", err)
	}
}

func TestValidateResponseRejectsTransactionIDMismatch(t *testing.T) {
	q, r := validPair()
	r.Id++
	if err := ValidateResponse(q, r, true); err == nil {
		t.Fatal("expected transaction ID mismatch")
	}
}

func TestValidateResponseRejectsQuestionMismatch(t *testing.T) {
	q, r := validPair()
	r.Question[0].Qtype = dns.TypeNS
	if err := ValidateResponse(q, r, true); err == nil {
		t.Fatal("expected question mismatch")
	}
}

func TestValidateResponseRequiresAAWhenRequested(t *testing.T) {
	q, r := validPair()
	r.Authoritative = false
	if err := ValidateResponse(q, r, true); err == nil {
		t.Fatal("expected AA validation failure")
	}
	if err := ValidateResponse(q, r, false); err != nil {
		t.Fatalf("AA should be optional when not requested: %v", err)
	}
}

func TestClassifyResponse(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		rcode     int
		truncated bool
		want      string
	}{
		{name: "NOERROR", rcode: dns.RcodeSuccess, want: "DNS_NOERROR"},
		{name: "NXDOMAIN", rcode: dns.RcodeNameError, want: "DNS_NXDOMAIN"},
		{name: "REFUSED", rcode: dns.RcodeRefused, want: "DNS_REFUSED"},
		{name: "SERVFAIL", rcode: dns.RcodeServerFailure, want: "DNS_SERVFAIL"},
		{name: "other RCODE", rcode: dns.RcodeNotImplemented, want: "DNS_OTHER_RCODE"},
		{name: "truncated response", rcode: dns.RcodeSuccess, truncated: true, want: "TRUNCATED"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := new(dns.Msg)
			response.Rcode = testCase.rcode
			response.Truncated = testCase.truncated
			if got := classifyResponse(response); got != testCase.want {
				t.Fatalf("classifyResponse=%q, want %q", got, testCase.want)
			}
		})
	}
}

func TestAnswerRRStrings(t *testing.T) {
	answer, err := dns.NewRR("highway.odot.state.or.us. 300 IN A 159.121.71.106")
	if err != nil {
		t.Fatal(err)
	}
	got := answerRRStrings([]dns.RR{answer})
	if len(got) != 1 || got[0] != "highway.odot.state.or.us.\t300\tIN\tA\t159.121.71.106" {
		t.Fatalf("answerRRStrings=%q", got)
	}
}

func TestSectionRRStringsIncludeReferralAndGlue(t *testing.T) {
	referral, err := dns.NewRR("highway.odot.state.or.us. 0 IN NS ns1.child.example.")
	if err != nil {
		t.Fatal(err)
	}
	glue, err := dns.NewRR("ns1.child.example. 300 IN A 192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	if got := answerRRStrings([]dns.RR{referral}); len(got) != 1 || !strings.Contains(got[0], "NS\tns1.child.example.") {
		t.Fatalf("authority record string=%q", got)
	}
	if got := answerRRStrings([]dns.RR{glue}); len(got) != 1 || !strings.Contains(got[0], "A\t192.0.2.53") {
		t.Fatalf("additional record string=%q", got)
	}
}

func TestClassifyExchangeError(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{name: "deadline", ctx: context.Background(), err: context.DeadlineExceeded, want: "TIMEOUT"},
		{name: "canceled", ctx: canceledContext(), err: context.Canceled, want: "CANCELED"},
		{name: "transport", ctx: context.Background(), err: errors.New("connection refused"), want: "TRANSPORT_ERROR"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := classifyExchangeError(testCase.ctx, testCase.err); got != testCase.want {
				t.Fatalf("classifyExchangeError=%q, want %q", got, testCase.want)
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestExtractSOA(t *testing.T) {
	q, r := validPair()
	_ = q
	soa, err := dns.NewRR("example.org. 300 IN SOA ns1.example.org. hostmaster.example.org. 2026110501 3600 600 86400 300")
	if err != nil {
		t.Fatal(err)
	}
	r.Answer = []dns.RR{soa}
	got := ExtractSOA(r)
	if got == nil || got.Serial != 2026110501 || got.MName != "ns1.example.org." {
		t.Fatalf("unexpected SOA extraction: %#v", got)
	}
}
