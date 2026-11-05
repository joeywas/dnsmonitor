package compliance

import "github.com/miekg/dns"

type Finding struct {
	Rule     string `json:"rule"`
	Standard string `json:"standard"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
}

// Evaluate only scores behavior that this particular probe can establish.
// A timeout is reported as an availability failure, not automatically as an
// RFC violation. Truncation compliance is evaluated only when TC is observed
// or a deliberately constrained response test is run.
func Evaluate(resp *dns.Msg, transport string) []Finding {
	findings := []Finding{}
	if resp == nil {
		return append(findings, Finding{"response_received", "RFC 1035", "FAIL", "No DNS response received"})
	}
	if !resp.Response {
		findings = append(findings, Finding{"qr_bit", "RFC 1035", "FAIL", "Response did not set QR"})
	} else {
		findings = append(findings, Finding{"qr_bit", "RFC 1035", "PASS", "Response bit set"})
	}
	if transport == "tcp" {
		findings = append(findings, Finding{"tcp_transport", "RFC 7766", "OBSERVED", "Valid DNS response received over TCP"})
	}
	if resp.Truncated && transport == "udp" {
		findings = append(findings, Finding{"udp_truncation", "RFC 1035", "OBSERVED", "Server set TC=1; client should retry over TCP"})
	}
	return findings
}
