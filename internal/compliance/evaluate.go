package compliance

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

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
		return append(findings, Finding{"response_received", "Monitor availability", "FAIL", "No DNS response received"})
	}
	if !resp.Response {
		findings = append(findings, Finding{"qr_bit", "RFC 1035", "FAIL", "Response did not set QR"})
	} else {
		findings = append(findings, Finding{"qr_bit", "RFC 1035", "PASS", "Response bit set"})
	}
	if resp.Rcode == dns.RcodeSuccess {
		findings = append(findings, Finding{"dns_rcode", "RFC 1035", "PASS", "NOERROR response received"})
	} else {
		rcode := dns.RcodeToString[resp.Rcode]
		if rcode == "" {
			rcode = "unknown"
		}
		findings = append(findings, Finding{"dns_rcode", "RFC 1035", "FAIL", "Expected NOERROR; received " + rcode})
	}
	if transport == "tcp" {
		findings = append(findings, Finding{"tcp_transport", "RFC 7766", "OBSERVED", "Valid DNS response received over TCP"})
	}
	if resp.Truncated && transport == "udp" {
		findings = append(findings, Finding{"udp_truncation", "RFC 2181 Section 9", "OBSERVED", "TC=1 observed; whether it was justified by an incomplete required RRset is assessed separately"})
	}
	return findings
}

// AssessTruncation compares UDP data with a complete TCP response. Answer and
// Authority records are treated as required; Additional records are optional.
func AssessTruncation(udpResponse, tcpResponse *dns.Msg) Finding {
	inconclusive := Finding{
		Rule: "tc_bit_compliance", Standard: "RFC 2181 Section 9", Status: "INCONCLUSIVE",
		Detail: "A comparable complete TCP response was unavailable",
	}
	if udpResponse == nil || tcpResponse == nil || !udpResponse.Response || !tcpResponse.Response || tcpResponse.Truncated {
		return inconclusive
	}
	if len(udpResponse.Question) != 1 || len(tcpResponse.Question) != 1 {
		return inconclusive
	}
	udpQuestion, tcpQuestion := udpResponse.Question[0], tcpResponse.Question[0]
	if !strings.EqualFold(dns.Fqdn(udpQuestion.Name), dns.Fqdn(tcpQuestion.Name)) ||
		udpQuestion.Qtype != tcpQuestion.Qtype || udpQuestion.Qclass != tcpQuestion.Qclass ||
		udpResponse.Rcode != tcpResponse.Rcode {
		return inconclusive
	}

	udpRecords := requiredRecords(udpResponse)
	tcpRecords := requiredRecords(tcpResponse)
	missing, extra := false, false
	for record := range tcpRecords {
		if _, ok := udpRecords[record]; !ok {
			missing = true
			break
		}
	}
	for record := range udpRecords {
		if _, ok := tcpRecords[record]; !ok {
			extra = true
			break
		}
	}
	if extra {
		return Finding{
			Rule: "tc_bit_compliance", Standard: "RFC 2181 Section 9", Status: "INCONCLUSIVE",
			Detail: "UDP contains required RR data absent from the TCP reference",
		}
	}

	switch {
	case udpResponse.Truncated && missing:
		return Finding{"tc_bit_compliance", "RFC 2181 Section 9", "PASS", "TC=1 and TCP contains required Answer or Authority records absent from UDP"}
	case udpResponse.Truncated:
		return Finding{"tc_bit_compliance", "RFC 2181 Section 9", "FAIL", "TC=1 although no required Answer or Authority records are missing from UDP"}
	case missing:
		return Finding{"tc_bit_compliance", "RFC 2181 Section 9", "FAIL", "TC=0 but TCP contains required Answer or Authority records absent from UDP"}
	default:
		return Finding{"tc_bit_compliance", "RFC 2181 Section 9", "PASS", "TC=0 and TCP confirms all required Answer and Authority records were present in UDP"}
	}
}

func requiredRecords(msg *dns.Msg) map[string]struct{} {
	records := make(map[string]struct{}, len(msg.Answer)+len(msg.Ns))
	for sectionIndex, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			copy := dns.Copy(rr)
			copy.Header().Ttl = 0
			records[fmt.Sprintf("%d:%s", sectionIndex, copy.String())] = struct{}{}
		}
	}
	return records
}
