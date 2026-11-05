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
	ServerName         string               `json:"server_name"`
	ServerIP           string               `json:"server_ip"`
	QName              string               `json:"qname"`
	QType              string               `json:"qtype"`
	Attempts           []dnsprobe.Attempt   `json:"attempts"`
	Findings           []compliance.Finding `json:"findings"`
	SOA                *dnsprobe.SOAData    `json:"soa,omitempty"`
	RetryAssessment    string               `json:"retry_assessment,omitempty"`
	FallbackAssessment string               `json:"fallback_assessment,omitempty"`
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
					qname := zone.ZoneName
					if qtype == dns.TypeA || qtype == dns.TypeAAAA {
						qname = dns.Fqdn(target.Hostname)
					}
					test := TestResult{
						ServerName: ns.Name, ServerIP: ip, QName: qname, QType: dns.TypeToString[qtype],
						FallbackAssessment: "NOT_EXERCISED",
					}

					// UDP retries are monitor policy. We only report a retry recovery
					// when the first attempt failed and a later attempt succeeded.
					firstUDPSuccess := false
					recovered := false
					var udpResponse *dns.Msg
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
					tcp, _, tcpResp := dnsprobe.Query(ctx, server, qname, qtype, "tcp",
						time.Duration(target.Timeout), target.EDNSUDPSize, target.RecursionDesired, 1)
					test.Attempts = append(test.Attempts, tcp)
					if tcp.Success {
						test.Findings = append(test.Findings, compliance.Evaluate(tcpResp, "tcp")...)
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
