package dnsprobe

import (
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
