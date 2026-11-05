package monitoring

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"dns-monitor/internal/compliance"
	"dns-monitor/internal/config"
	"dns-monitor/internal/discovery"
	"dns-monitor/internal/dnsprobe"
	"github.com/miekg/dns"
)

type RunResult struct {
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Target     string         `json:"target"`
	Discovery  discovery.Zone `json:"discovery"`
	Tests      []TestResult   `json:"tests"`
	Errors     []string       `json:"errors,omitempty"`
}
type TestResult struct {
	ServerName string               `json:"server_name"`
	ServerIP   string               `json:"server_ip"`
	QName      string               `json:"qname"`
	QType      string               `json:"qtype"`
	Attempts   []dnsprobe.Attempt   `json:"attempts"`
	Findings   []compliance.Finding `json:"findings"`
}

func Run(ctx context.Context, cfg config.File) ([]RunResult, error) {
	results := []RunResult{}
	var runErr error
	for _, target := range cfg.Targets {
		r := RunResult{StartedAt: time.Now().UTC(), Target: target.Hostname}
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
						qname = target.Hostname
					}
					test := TestResult{ServerName: ns.Name, ServerIP: ip, QName: qname, QType: dns.TypeToString[qtype]}
					for attempt := 1; attempt <= target.UDPRetries+1; attempt++ {
						a, resp := dnsprobe.Query(ctx, server, qname, qtype, "udp", time.Duration(target.Timeout), target.EDNSUDPSize, target.RecursionDesired, attempt)
						test.Attempts = append(test.Attempts, a)
						if a.Success {
							if resp.Truncated {
								tcp, tcpResp := dnsprobe.Query(ctx, server, qname, qtype, "tcp", time.Duration(target.Timeout), 0, target.RecursionDesired, 1)
								test.Attempts = append(test.Attempts, tcp)
								test.Findings = append(test.Findings, compliance.Evaluate(tcpResp, "tcp")...)
							}
							test.Findings = append(test.Findings, compliance.Evaluate(resp, "udp")...)
							break
						}
					}
					// Independent TCP baseline: TCP must be tested even if UDP succeeded.
					tcp, tcpResp := dnsprobe.Query(ctx, server, qname, qtype, "tcp", time.Duration(target.Timeout), target.EDNSUDPSize, target.RecursionDesired, 1)
					test.Attempts = append(test.Attempts, tcp)
					test.Findings = append(test.Findings, compliance.Evaluate(tcpResp, "tcp")...)
					r.Tests = append(r.Tests, test)
				}
			}
		}
		r.FinishedAt = time.Now().UTC()
		results = append(results, r)
	}
	return results, runErr
}
