package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Nameserver struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

type Zone struct {
	QueriedName string       `json:"queried_name"`
	ZoneName    string       `json:"zone_name"`
	Nameservers []Nameserver `json:"nameservers"`
	Discovery   string       `json:"discovery_method"`
}

// Discover walks from the queried hostname toward the root, looking for the
// closest enclosing SOA. The recursive system resolver is used only for
// discovery; all measurements afterwards go directly to authoritative IPs.
func Discover(ctx context.Context, hostname string) (Zone, error) {
	qname := dns.Fqdn(strings.TrimSpace(hostname))
	labels := dns.SplitDomainName(qname)
	if len(labels) == 0 {
		return Zone{}, fmt.Errorf("invalid hostname %q", hostname)
	}

	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	var zoneName string
	for i := 0; i < len(labels); i++ {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		m := new(dns.Msg)
		m.SetQuestion(candidate, dns.TypeSOA)
		resp, _, err := client.ExchangeContext(ctx, m, systemResolverAddress())
		if err != nil || resp == nil {
			continue
		}
		// For a name below a zone, a recursive server commonly returns the
		// enclosing zone's SOA in the authority section (NODATA response).
		for _, section := range [][]dns.RR{resp.Answer, resp.Ns} {
			for _, rr := range section {
				soa, ok := rr.(*dns.SOA)
				if !ok {
					continue
				}
				owner := dns.Fqdn(soa.Hdr.Name)
				if candidate == owner || dns.IsSubDomain(owner, candidate) {
					zoneName = owner
					break
				}
			}
			if zoneName != "" {
				break
			}
		}
		if zoneName != "" {
			break
		}
	}
	if zoneName == "" {
		return Zone{}, fmt.Errorf("could not discover authoritative SOA zone for %s", qname)
	}

	resolver := &net.Resolver{}
	nsRecords, err := resolver.LookupNS(ctx, strings.TrimSuffix(zoneName, "."))
	if err != nil {
		return Zone{}, fmt.Errorf("NS lookup for %s: %w", zoneName, err)
	}
	seen := map[string]bool{}
	out := Zone{QueriedName: qname, ZoneName: zoneName, Discovery: "recursive-resolver SOA walk + NS lookup"}
	for _, record := range nsRecords {
		name := dns.Fqdn(record.Host)
		if seen[name] {
			continue
		}
		seen[name] = true
		entry := Nameserver{Name: name}
		ips, lookupErr := resolver.LookupIPAddr(ctx, strings.TrimSuffix(name, "."))
		if lookupErr == nil {
			for _, ip := range ips {
				entry.IPs = append(entry.IPs, ip.IP.String())
			}
		}
		out.Nameservers = append(out.Nameservers, entry)
	}
	if len(out.Nameservers) == 0 {
		return Zone{}, fmt.Errorf("no NS records discovered for %s", zoneName)
	}
	return out, nil
}

// Use the host's configured recursive resolver address for discovery only.
func systemResolverAddress() string {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(conf.Servers) > 0 {
		port := conf.Port
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(conf.Servers[0], port)
	}
	return "127.0.0.1:53"
}
