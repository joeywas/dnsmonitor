package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"dns-monitor/internal/compliance"
	"dns-monitor/internal/config"
	"dns-monitor/internal/discovery"
	"dns-monitor/internal/dnsprobe"

	"github.com/miekg/dns"
)

type RunResult struct {
	StartedAt           time.Time      `json:"started_at"`
	FinishedAt          time.Time      `json:"finished_at"`
	Target              string         `json:"target"`
	SourceIP            string         `json:"source_ip,omitempty"`
	SourceRegionName    string         `json:"source_region_name,omitempty"`
	SourceCity          string         `json:"source_city,omitempty"`
	SourceASN           string         `json:"source_asn,omitempty"`
	SourceASNOrg        string         `json:"source_asn_org,omitempty"`
	SourceIPLookupError string         `json:"source_ip_lookup_error,omitempty"`
	Discovery           discovery.Zone `json:"discovery"`
	Tests               []TestResult   `json:"tests"`
	Errors              []string       `json:"errors,omitempty"`
}

type TestResult struct {
	ServerName                  string               `json:"server_name"`
	ServerIP                    string               `json:"server_ip"`
	QName                       string               `json:"qname"`
	QType                       string               `json:"qtype"`
	Attempts                    []dnsprobe.Attempt   `json:"attempts"`
	Findings                    []compliance.Finding `json:"findings"`
	SOA                         *dnsprobe.SOAData    `json:"soa,omitempty"`
	RetryAssessment             string               `json:"retry_assessment,omitempty"`
	FallbackAssessment          string               `json:"fallback_assessment,omitempty"`
	ExpectedAnswerAssessment    string               `json:"expected_answer_assessment"`
	ExpectedAnswerTCPAssessment string               `json:"expected_answer_tcp_assessment"`
	ReferralAssessment          string               `json:"referral_assessment"`
}

type publicIPInfo struct {
	IP         string `json:"ip"`
	RegionName string `json:"region_name"`
	City       string `json:"city"`
	ASN        string `json:"asn"`
	ASNOrg     string `json:"asn_org"`
}

const publicIPEndpoint = "https://ipconfig.io/json"

func Run(ctx context.Context, cfg config.File) ([]RunResult, error) {
	results := []RunResult{}
	var runErr error
	source, sourceIPErr := lookupPublicIP(ctx, publicIPEndpoint)
	for _, target := range cfg.Targets {
		r := RunResult{
			StartedAt: time.Now().UTC(), Target: target.Hostname,
			SourceIP: source.IP, SourceRegionName: source.RegionName, SourceCity: source.City,
			SourceASN: source.ASN, SourceASNOrg: source.ASNOrg,
		}
		if sourceIPErr != nil {
			r.SourceIPLookupError = sourceIPErr.Error()
		}
		zone, err := discovery.Discover(ctx, target.Hostname)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
			runErr = fmt.Errorf("discovery for %s: %w", target.Hostname, err)
			r.FinishedAt = time.Now().UTC()
			results = append(results, r)
			continue
		}
		r.Discovery = zone
		for _, ns := range zone.Nameservers {
			for _, ip := range ns.IPs {
				server := net.JoinHostPort(ip, "53")
				for _, qt := range target.RecordTypes {
					qtype := dns.StringToType[strings.ToUpper(qt)]
					if qtype == 0 {
						r.Errors = append(r.Errors, "unsupported record type: "+qt)
						continue
					}
					qname := queryNameForType(zone.ZoneName, target.Hostname, qtype)
					test := TestResult{
						ServerName: ns.Name, ServerIP: ip, QName: qname, QType: dns.TypeToString[qtype],
						FallbackAssessment:          "NOT_EXERCISED",
						ExpectedAnswerAssessment:    "NOT_CONFIGURED",
						ExpectedAnswerTCPAssessment: "NOT_CONFIGURED",
						ReferralAssessment:          "NOT_NEEDED",
					}

					// UDP retries are monitor policy. We only report a retry recovery
					// when the first attempt failed and a later attempt succeeded.
					firstUDPSuccess := false
					recovered := false
					var udpResponse *dns.Msg
					var expectedAnswerResponse *dns.Msg
					var lastUDPAttempt dnsprobe.Attempt
					for attempt := 1; attempt <= target.UDPRetries+1; attempt++ {
						a, _, resp := dnsprobe.Query(ctx, server, qname, qtype, "udp",
							time.Duration(target.Timeout), target.EDNSUDPSize, target.RecursionDesired, attempt)
						test.Attempts = append(test.Attempts, a)
						lastUDPAttempt = a
						if attempt == 1 {
							firstUDPSuccess = a.Success
						}
						if a.Success {
							udpResponse = resp
							expectedAnswerResponse = resp
							if attempt > 1 {
								recovered = true
							}
							break
						}
						if ctx.Err() != nil {
							break
						}
					}
					switch {
					case ctx.Err() != nil && udpResponse == nil:
						test.RetryAssessment = "INCONCLUSIVE"
						test.Findings = append(test.Findings, compliance.Finding{
							Rule: "udp_retry_policy", Standard: "Monitor policy", Status: "INCONCLUSIVE",
							Detail: "Probe context was cancelled before the retry sequence completed",
						})
					case firstUDPSuccess:
						test.RetryAssessment = "INCONCLUSIVE"
						test.Findings = append(test.Findings, compliance.Finding{
							Rule: "udp_retry_policy", Standard: "Monitor policy", Status: "INCONCLUSIVE",
							Detail: "Initial UDP attempt succeeded; retry behavior was not exercised",
						})
					case recovered:
						test.RetryAssessment = "PASS"
						test.Findings = append(test.Findings, compliance.Finding{
							Rule: "udp_retry_policy", Standard: "Monitor policy", Status: "PASS",
							Detail: "Initial UDP attempt failed and a subsequent configured attempt succeeded",
						})
					default:
						test.RetryAssessment = "FAIL"
						test.Findings = append(test.Findings, compliance.Finding{
							Rule: "udp_retry_policy", Standard: "Monitor policy", Status: "FAIL",
							Detail: "No valid UDP response was received within the configured attempt limit",
						})
					}
					var tcpFallbackResponse *dns.Msg
					if udpResponse != nil {
						test.Findings = append(test.Findings, compliance.Evaluate(udpResponse, "udp")...)
						fallback, tcpResp, fallbackAttempted := queryTCPFallback(ctx, server, qname, qtype,
							time.Duration(target.Timeout), target.EDNSUDPSize, target.RecursionDesired, udpResponse)
						if fallbackAttempted {
							test.Attempts = append(test.Attempts, fallback)
							switch {
							case !fallback.Success:
								test.FallbackAssessment = "FAIL"
							case tcpResp.Truncated:
								test.FallbackAssessment = "FAIL"
							default:
								test.FallbackAssessment = "PASS"
							}
							if fallback.Success {
								tcpFallbackResponse = tcpResp
								if !tcpResp.Truncated {
									expectedAnswerResponse = tcpResp
								}
								test.Findings = append(test.Findings, compliance.Evaluate(tcpResp, "tcp")...)
							} else {
								test.Findings = append(test.Findings, validationFinding(fallback))
							}
							test.Findings = append(test.Findings, compliance.Finding{
								Rule: "udp_to_tcp_fallback", Standard: "RFC 7766", Status: test.FallbackAssessment,
								Detail: "TCP retry after a truncated UDP response",
							})
						}
						if qtype == dns.TypeSOA {
							test.SOA = extractUsableSOA(udpResponse, tcpFallbackResponse)
						}
					} else if lastUDPAttempt.Received {
						test.Findings = append(test.Findings, validationFinding(lastUDPAttempt))
					} else {
						test.Findings = append(test.Findings, compliance.Evaluate(nil, "udp")...)
					}

					// Independent TCP baseline; this is deliberately separate from fallback.
					var tcpExpectedAnswerResponse *dns.Msg
					tcp, _, tcpResp := dnsprobe.Query(ctx, server, qname, qtype, "tcp",
						time.Duration(target.Timeout), target.EDNSUDPSize, target.RecursionDesired, 1)
					test.Attempts = append(test.Attempts, tcp)
					if tcp.Success {
						test.Findings = append(test.Findings, compliance.Evaluate(tcpResp, "tcp")...)
						if !tcpResp.Truncated {
							tcpExpectedAnswerResponse = tcpResp
						}
						if qtype == dns.TypeSOA && test.SOA == nil && !tcpResp.Truncated {
							test.SOA = dnsprobe.ExtractSOA(tcpResp)
						}
					} else if tcp.Received {
						test.Findings = append(test.Findings, validationFinding(tcp))
					} else {
						test.Findings = append(test.Findings, compliance.Evaluate(nil, "tcp")...)
					}
					var tcpReference *dns.Msg
					if udpResponse != nil {
						if udpResponse.Truncated {
							tcpReference = tcpFallbackResponse
						} else if tcp.Success {
							tcpReference = tcpResp
						}
					}
					test.Findings = append(test.Findings, compliance.AssessTruncation(udpResponse, tcpReference))
					if expected, ok := target.ExpectedAnswers[strings.ToUpper(qt)]; ok {
						referral := followReferrals(ctx, qname, qtype, target.Timeout,
							target.EDNSUDPSize, target.RecursionDesired, expectedAnswerResponse, dnsprobe.Query, resolveReferralIPs)
						test.ReferralAssessment = referral.Assessment
						test.Attempts = append(test.Attempts, referral.Attempts...)
						expectedAnswerResponse = referral.Response
						if referral.Error != "" {
							status := "FAIL"
							if referral.Assessment == "INCONCLUSIVE" {
								status = "INCONCLUSIVE"
							}
							test.Findings = append(test.Findings, compliance.Finding{
								Rule: "delegation_referral", Standard: "DNS delegation", Status: status, Detail: referral.Error,
							})
						}
						finding := assessExpectedAnswer(qtype, expected, expectedAnswerResponse)
						test.ExpectedAnswerAssessment = finding.Status
						test.Findings = append(test.Findings, finding)
						tcpFinding := assessExpectedAnswer(qtype, expected, tcpExpectedAnswerResponse)
						tcpFinding.Rule = "expected_answer_tcp"
						tcpFinding.Detail = "TCP baseline: " + tcpFinding.Detail
						test.ExpectedAnswerTCPAssessment = tcpFinding.Status
						test.Findings = append(test.Findings, tcpFinding)
					}
					r.Tests = append(r.Tests, test)
				}
			}
		}
		compareSOASerials(&r)
		r.FinishedAt = time.Now().UTC()
		results = append(results, r)
	}
	return results, runErr
}

const maxReferralHops = 5

type referralQuery func(context.Context, string, string, uint16, string, time.Duration, uint16, bool, int) (dnsprobe.Attempt, *dns.Msg, *dns.Msg)
type referralIPResolver func(context.Context, string) ([]string, error)

type referralResult struct {
	Assessment string
	Attempts   []dnsprobe.Attempt
	Response   *dns.Msg
	Error      string
}

func followReferrals(ctx context.Context, qname string, qtype uint16, timeout config.Duration, ednsSize uint16, rd bool, initialResponse *dns.Msg, query referralQuery, resolveIPs referralIPResolver) referralResult {
	result := referralResult{Assessment: "NOT_NEEDED", Response: initialResponse}
	visited := map[string]bool{}

	for hop := 0; hop < maxReferralHops; hop++ {
		targets := referralTargets(result.Response, qname)
		if len(targets) == 0 {
			if hop > 0 {
				result.Assessment = "FOLLOWED"
			}
			return result
		}
		result.Assessment = "FAILED"
		delegationKey := strings.ToLower(strings.Join(targets, ","))
		if visited[delegationKey] {
			result.Assessment = "INCONCLUSIVE"
			result.Error = "Delegation referral loop detected"
			return result
		}
		visited[delegationKey] = true

		advanced := false
		var lastError string
		for _, target := range targets {
			ips := referralGlueIPs(result.Response, target)
			if len(ips) == 0 {
				resolveCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout))
				resolvedIPs, err := resolveIPs(resolveCtx, target)
				cancel()
				if err != nil {
					lastError = fmt.Sprintf("resolve delegated nameserver %s: %v", target, err)
					continue
				}
				ips = resolvedIPs
			}
			if len(ips) == 0 {
				lastError = fmt.Sprintf("delegated nameserver %s has no usable A or AAAA addresses", target)
				continue
			}
			for _, ip := range ips {
				destination := net.JoinHostPort(ip, "53")
				attempt, _, response := query(ctx, destination, qname, qtype, "udp", time.Duration(timeout), ednsSize, rd, 1)
				result.Attempts = append(result.Attempts, attempt)
				if !attempt.Success || response == nil {
					lastError = fmt.Sprintf("query delegated nameserver %s at %s failed: %s", target, destination, attemptError(attempt))
					continue
				}
				result.Response = response
				advanced = true
				break
			}
			if advanced {
				break
			}
		}
		if !advanced {
			result.Error = lastError
			return result
		}
	}

	if len(referralTargets(result.Response, qname)) > 0 {
		result.Assessment = "INCONCLUSIVE"
		result.Error = fmt.Sprintf("Referral hop limit (%d) reached", maxReferralHops)
		return result
	}
	result.Assessment = "FOLLOWED"
	return result
}

func referralTargets(response *dns.Msg, qname string) []string {
	if response == nil || response.Truncated || response.Rcode != dns.RcodeSuccess ||
		len(response.Answer) != 0 || len(response.Question) != 1 {
		return nil
	}
	for _, record := range response.Ns {
		if _, ok := record.(*dns.SOA); ok {
			return nil
		}
	}
	qname = dns.Fqdn(qname)
	longestOwnerLabels := -1
	targets := []string{}
	seen := map[string]bool{}
	for _, record := range response.Ns {
		ns, ok := record.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.Fqdn(ns.Hdr.Name)
		if !dns.IsSubDomain(owner, qname) {
			continue
		}
		ownerLabels := len(dns.SplitDomainName(owner))
		target := dns.Fqdn(ns.Ns)
		switch {
		case ownerLabels > longestOwnerLabels:
			longestOwnerLabels = ownerLabels
			targets = []string{target}
			seen = map[string]bool{strings.ToLower(target): true}
		case ownerLabels == longestOwnerLabels && !seen[strings.ToLower(target)]:
			targets = append(targets, target)
			seen[strings.ToLower(target)] = true
		}
	}
	return targets
}

func referralGlueIPs(response *dns.Msg, nameserver string) []string {
	if response == nil {
		return nil
	}
	want := strings.ToLower(dns.Fqdn(nameserver))
	ips := []string{}
	seen := map[string]bool{}
	for _, record := range response.Extra {
		if strings.ToLower(dns.Fqdn(record.Header().Name)) != want {
			continue
		}
		var ip net.IP
		switch address := record.(type) {
		case *dns.A:
			ip = address.A.To4()
		case *dns.AAAA:
			if address.AAAA.To4() == nil {
				ip = address.AAAA.To16()
			}
		}
		if ip == nil {
			continue
		}
		value := ip.String()
		if !seen[value] {
			ips = append(ips, value)
			seen[value] = true
		}
	}
	return ips
}

func resolveReferralIPs(ctx context.Context, nameserver string) ([]string, error) {
	resolver := &net.Resolver{}
	addresses, err := resolver.LookupIPAddr(ctx, strings.TrimSuffix(dns.Fqdn(nameserver), "."))
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, address.IP.String())
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A or AAAA addresses found")
	}
	return ips, nil
}

func attemptError(attempt dnsprobe.Attempt) string {
	if attempt.ValidationError != "" {
		return attempt.ValidationError
	}
	if attempt.Error != "" {
		return attempt.Error
	}
	return attempt.Outcome
}

func queryNameForType(zoneName, hostname string, qtype uint16) string {
	if qtype == dns.TypeSOA || qtype == dns.TypeNS {
		return dns.Fqdn(zoneName)
	}
	return dns.Fqdn(hostname)
}

func assessExpectedAnswer(qtype uint16, expected config.ExpectedAnswer, response *dns.Msg) compliance.Finding {
	failure := func(detail string) compliance.Finding {
		return compliance.Finding{
			Rule: "expected_answer", Standard: "Configured target expectation", Status: "FAIL", Detail: detail,
		}
	}
	if response == nil {
		return failure("No valid UDP response or complete TCP fallback response was available")
	}
	if response.Truncated {
		return failure("Only a truncated response was available")
	}
	if referral := referralTarget(response); referral != "" {
		return compliance.Finding{
			Rule: "expected_answer", Standard: "Configured target expectation", Status: "INCONCLUSIVE",
			Detail: fmt.Sprintf("Response is a delegation referral to %s; the expected answer requires querying that nameserver", referral),
		}
	}
	expectedRcode, ok := dns.StringToRcode[strings.ToUpper(expected.RCode)]
	if !ok {
		return compliance.Finding{
			Rule: "expected_answer", Standard: "Configured target expectation", Status: "INCONCLUSIVE",
			Detail: fmt.Sprintf("Unsupported configured RCODE %q", expected.RCode),
		}
	}
	if response.Rcode != expectedRcode {
		return failure(fmt.Sprintf("Expected RCODE %s, received %s", expected.RCode, dns.RcodeToString[response.Rcode]))
	}

	want := make(map[string]struct{}, len(expected.Answers))
	for _, answer := range expected.Answers {
		want[answer] = struct{}{}
	}
	got := map[string]struct{}{}
	for _, rr := range response.Answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		if answer, err := config.NormalizeAnswerRR(rr); err == nil {
			got[answer] = struct{}{}
		}
	}
	if len(got) != len(want) {
		return failure(fmt.Sprintf("Expected %d %s answer(s), received %d", len(want), dns.TypeToString[qtype], len(got)))
	}
	for answer := range want {
		if _, ok := got[answer]; !ok {
			return failure(fmt.Sprintf("Expected %s answer %s was not returned", dns.TypeToString[qtype], answer))
		}
	}
	return compliance.Finding{
		Rule: "expected_answer", Standard: "Configured target expectation", Status: "PASS",
		Detail: fmt.Sprintf("Received expected %s RCODE and answer set", expected.RCode),
	}
}

func referralTarget(response *dns.Msg) string {
	if response == nil || len(response.Answer) != 0 || len(response.Question) != 1 {
		return ""
	}
	for _, record := range response.Ns {
		if _, ok := record.(*dns.SOA); ok {
			return ""
		}
	}
	qname := dns.Fqdn(response.Question[0].Name)
	var target string
	longestOwnerLabels := -1
	for _, record := range response.Ns {
		ns, ok := record.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.Fqdn(ns.Hdr.Name)
		if !dns.IsSubDomain(owner, qname) {
			continue
		}
		ownerLabels := len(dns.SplitDomainName(owner))
		if ownerLabels > longestOwnerLabels {
			longestOwnerLabels = ownerLabels
			target = dns.Fqdn(ns.Ns)
		}
	}
	return target
}

func lookupPublicIP(ctx context.Context, endpoint string) (publicIPInfo, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return publicIPInfo{}, fmt.Errorf("create public IP request: %w", err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return publicIPInfo{}, fmt.Errorf("request public IP: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return publicIPInfo{}, fmt.Errorf("public IP endpoint returned HTTP %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return publicIPInfo{}, fmt.Errorf("read public IP response: %w", err)
	}
	if len(body) > 4096 {
		return publicIPInfo{}, fmt.Errorf("public IP response is too large")
	}
	var info publicIPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return publicIPInfo{}, fmt.Errorf("decode public IP response: %w", err)
	}
	ip := net.ParseIP(strings.TrimSpace(info.IP))
	if ip == nil {
		return publicIPInfo{}, fmt.Errorf("public IP endpoint returned an invalid IP address")
	}
	info.IP = ip.String()
	info.RegionName = strings.TrimSpace(info.RegionName)
	info.City = strings.TrimSpace(info.City)
	info.ASN = strings.TrimSpace(info.ASN)
	info.ASNOrg = strings.TrimSpace(info.ASNOrg)
	return info, nil
}

func queryTCPFallback(ctx context.Context, server, qname string, qtype uint16, timeout time.Duration, ednsSize uint16, rd bool, udpResponse *dns.Msg) (dnsprobe.Attempt, *dns.Msg, bool) {
	if udpResponse == nil || !udpResponse.Truncated {
		return dnsprobe.Attempt{}, nil, false
	}
	attempt, _, response := dnsprobe.Query(ctx, server, qname, qtype, "tcp", timeout, ednsSize, rd, 1)
	return attempt, response, true
}

func extractUsableSOA(udpResponse, fallbackResponse *dns.Msg) *dnsprobe.SOAData {
	if udpResponse != nil && !udpResponse.Truncated {
		return dnsprobe.ExtractSOA(udpResponse)
	}
	if fallbackResponse != nil && !fallbackResponse.Truncated {
		return dnsprobe.ExtractSOA(fallbackResponse)
	}
	return nil
}

func compareSOASerials(run *RunResult) {
	serials := map[string]uint32{}
	inconsistentWithinServer := map[string]bool{}
	for i := range run.Tests {
		test := &run.Tests[i]
		if test.QType != "SOA" || test.SOA == nil {
			continue
		}
		if previous, ok := serials[test.ServerName]; ok && previous != test.SOA.Serial {
			inconsistentWithinServer[test.ServerName] = true
		} else {
			serials[test.ServerName] = test.SOA.Serial
		}
	}

	status := "PASS"
	detail := "All responding authoritative nameservers reported the same SOA serial"
	switch {
	case len(serials) < 2:
		status = "INCONCLUSIVE"
		detail = "Fewer than two nameservers returned a valid SOA record"
	case len(inconsistentWithinServer) > 0:
		status = "FAIL"
		detail = "A nameserver returned different SOA serials during the same probe run"
	default:
		names := make([]string, 0, len(serials))
		for name := range serials {
			names = append(names, name)
		}
		sort.Strings(names)
		firstName := names[0]
		firstSerial := serials[firstName]
		for _, name := range names[1:] {
			serial := serials[name]
			if serial != firstSerial {
				status = "FAIL"
				detail = fmt.Sprintf("SOA serial mismatch: %s returned %d; %s returned %d",
					firstName, firstSerial, name, serial)
				break
			}
		}
	}

	for i := range run.Tests {
		test := &run.Tests[i]
		if test.QType != "SOA" {
			continue
		}
		test.Findings = append(test.Findings, compliance.Finding{
			Rule: "soa_serial_consistency", Standard: "DNS zone operations",
			Status: status, Detail: detail,
		})
	}
}

func validationFinding(attempt dnsprobe.Attempt) compliance.Finding {
	detail := attempt.ValidationError
	if detail == "" {
		detail = attempt.Error
	}
	return compliance.Finding{
		Rule: "response_validation", Standard: "RFC 1035", Status: "FAIL",
		Detail: detail,
	}
}
