package monitoring

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dns-monitor/internal/config"
	"dns-monitor/internal/dnsprobe"

	"github.com/miekg/dns"
)

func TestQueryTCPFallbackAfterTruncatedUDPResponse(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		udpTruncated bool
		wantFallback bool
	}{
		{name: "truncated UDP triggers TCP", udpTruncated: true, wantFallback: true},
		{name: "complete UDP skips TCP fallback", udpTruncated: false, wantFallback: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server, udpQueries, tcpQueries := startFallbackTestServer(t, testCase.udpTruncated)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			udpAttempt, _, udpResponse := dnsprobe.Query(ctx, server, "example.test.", dns.TypeA, "udp", time.Second, 1232, false, 1)
			if !udpAttempt.Success {
				t.Fatalf("UDP query failed: %#v", udpAttempt)
			}
			if udpResponse.Truncated != testCase.udpTruncated {
				t.Fatalf("UDP TC=%t, want %t", udpResponse.Truncated, testCase.udpTruncated)
			}

			fallback, tcpResponse, attempted := queryTCPFallback(ctx, server, "example.test.", dns.TypeA, time.Second, 1232, false, udpResponse)
			if attempted != testCase.wantFallback {
				t.Fatalf("fallback attempted=%t, want %t", attempted, testCase.wantFallback)
			}
			if testCase.wantFallback {
				if !fallback.Success || fallback.Transport != "tcp" {
					t.Fatalf("TCP fallback failed: %#v", fallback)
				}
				if tcpResponse == nil || tcpResponse.Truncated {
					t.Fatalf("expected complete TCP response, got %#v", tcpResponse)
				}
			}
			if got := udpQueries.Load(); got != 1 {
				t.Errorf("UDP queries=%d, want 1", got)
			}
			wantTCPQueries := int32(0)
			if testCase.wantFallback {
				wantTCPQueries = 1
			}
			if got := tcpQueries.Load(); got != wantTCPQueries {
				t.Errorf("TCP queries=%d, want %d", got, wantTCPQueries)
			}
		})
	}
}

func TestExtractUsableSOAIgnoresTruncatedUDPData(t *testing.T) {
	udpResponse := soaResponse(t, 10)
	udpResponse.Truncated = true
	tcpResponse := soaResponse(t, 20)

	got := extractUsableSOA(udpResponse, tcpResponse)
	if got == nil || got.Serial != 20 {
		t.Fatalf("SOA serial=%v, want 20 from TCP fallback", got)
	}
	if got := extractUsableSOA(udpResponse, nil); got != nil {
		t.Fatalf("expected no SOA when truncated UDP has no complete fallback, got %#v", got)
	}
}

func TestLookupPublicIP(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		statusCode int
		body       string
		want       publicIPInfo
		wantErr    bool
	}{
		{
			name: "IPv4 and metadata", statusCode: http.StatusOK,
			body: `{"ip":"203.0.113.8","region_name":"Oregon","city":"McMinnville","asn":"AS13857","asn_org":"Online Northwest"}`,
			want: publicIPInfo{IP: "203.0.113.8", RegionName: "Oregon", City: "McMinnville", ASN: "AS13857", ASNOrg: "Online Northwest"},
		},
		{
			name: "IPv6", statusCode: http.StatusOK,
			body: `{"ip":"2001:db8::8","region_name":"Example","city":"Example City","asn":"AS64496","asn_org":"Example Network"}`,
			want: publicIPInfo{IP: "2001:db8::8", RegionName: "Example", City: "Example City", ASN: "AS64496", ASNOrg: "Example Network"},
		},
		{name: "invalid response", statusCode: http.StatusOK, body: "address unavailable", wantErr: true},
		{name: "HTTP failure", statusCode: http.StatusServiceUnavailable, body: "unavailable", wantErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(testCase.statusCode)
				_, _ = writer.Write([]byte(testCase.body))
			}))
			defer server.Close()

			got, err := lookupPublicIP(context.Background(), server.URL)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("lookupPublicIP error=%v, wantErr=%t", err, testCase.wantErr)
			}
			if got != testCase.want {
				t.Errorf("lookupPublicIP=%#v, want %#v", got, testCase.want)
			}
		})
	}
}

func TestAssessExpectedAnswer(t *testing.T) {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	response.Answer = []dns.RR{testARecord()}
	nodataResponse := new(dns.Msg)
	nodataResponse.Rcode = dns.RcodeSuccess
	nxdomainResponse := new(dns.Msg)
	nxdomainResponse.Rcode = dns.RcodeNameError

	tests := []struct {
		name       string
		expected   config.ExpectedAnswer
		response   *dns.Msg
		wantStatus string
	}{
		{
			name:     "exact answer matches",
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"192.0.2.1"}},
			response: response, wantStatus: "PASS",
		},
		{
			name:     "unexpected address fails",
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"192.0.2.2"}},
			response: response, wantStatus: "FAIL",
		},
		{
			name:     "empty expected set means NODATA",
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{}},
			response: response, wantStatus: "FAIL",
		},
		{
			name:     "empty response matches NODATA expectation",
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{}},
			response: nodataResponse, wantStatus: "PASS",
		},
		{
			name:     "rcode mismatch fails",
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"192.0.2.1"}},
			response: nxdomainResponse, wantStatus: "FAIL",
		},
		{
			name:     "missing response fails",
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"192.0.2.1"}},
			response: nil, wantStatus: "FAIL",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := assessExpectedAnswer(dns.TypeA, test.expected, test.response)
			if finding.Status != test.wantStatus {
				t.Fatalf("status=%s, want %s: %s", finding.Status, test.wantStatus, finding.Detail)
			}
		})
	}
}

func TestExpectedAnswerKeepsUDPAndTCPBaselineSeparate(t *testing.T) {
	expected := config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"192.0.2.1"}}
	udpResponse := new(dns.Msg)
	udpResponse.Rcode = dns.RcodeSuccess
	tcpResponse := new(dns.Msg)
	tcpResponse.Rcode = dns.RcodeSuccess
	tcpResponse.Answer = []dns.RR{testARecord()}

	udpFinding := assessExpectedAnswer(dns.TypeA, expected, udpResponse)
	tcpFinding := assessExpectedAnswer(dns.TypeA, expected, tcpResponse)
	if udpFinding.Status != "FAIL" {
		t.Fatalf("UDP assessment=%s, want FAIL", udpFinding.Status)
	}
	if tcpFinding.Status != "PASS" {
		t.Fatalf("TCP baseline assessment=%s, want PASS", tcpFinding.Status)
	}
}

func TestExpectedAnswerReportsDelegationReferral(t *testing.T) {
	response := new(dns.Msg)
	response.SetQuestion("highway.odot.state.or.us.", dns.TypeA)
	response.Response = true
	response.Rcode = dns.RcodeSuccess
	response.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "highway.odot.state.or.us.", Rrtype: dns.TypeNS, Class: dns.ClassINET},
		Ns:  "ck01.example.test.",
	}}
	expected := config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"159.121.71.106"}}

	finding := assessExpectedAnswer(dns.TypeA, expected, response)
	if finding.Status != "INCONCLUSIVE" || !strings.Contains(finding.Detail, "ck01.example.test.") {
		t.Fatalf("referral assessment=%#v, want inconclusive referral", finding)
	}
}

func TestFollowReferralsUsesGlueAndReachesExpectedAnswer(t *testing.T) {
	qname := "highway.odot.state.or.us."
	referral := testReferral(qname, "ck01.example.test.", "192.0.2.53")
	childResponse := testAResponse(qname, "159.121.71.106")
	query := func(_ context.Context, server, gotName string, qtype uint16, transport string, _ time.Duration, _ uint16, _ bool, attemptNumber int) (dnsprobe.Attempt, *dns.Msg, *dns.Msg) {
		if server != "192.0.2.53:53" || gotName != qname || qtype != dns.TypeA || transport != "udp" || attemptNumber != 1 {
			t.Fatalf("unexpected referral query: server=%s qname=%s qtype=%s transport=%s attempt=%d", server, gotName, dns.TypeToString[qtype], transport, attemptNumber)
		}
		return dnsprobe.Attempt{Transport: transport, Server: server, Success: true}, nil, childResponse
	}
	resolver := func(context.Context, string) ([]string, error) {
		t.Fatal("glue should avoid a separate nameserver lookup")
		return nil, nil
	}

	result := followReferrals(context.Background(), qname, dns.TypeA, config.Duration(time.Second), 1232, false, referral, query, resolver)
	if result.Assessment != "FOLLOWED" || len(result.Attempts) != 1 {
		t.Fatalf("unexpected referral result: %#v", result)
	}
	finding := assessExpectedAnswer(dns.TypeA, config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"159.121.71.106"}}, result.Response)
	if finding.Status != "PASS" {
		t.Fatalf("expected answer status=%s, want PASS: %s", finding.Status, finding.Detail)
	}
}

func TestFollowReferralsResolvesNameserverWithoutGlue(t *testing.T) {
	qname := "highway.odot.state.or.us."
	referral := testReferral(qname, "ck01.example.test.", "")
	childResponse := testAResponse(qname, "159.121.71.106")
	query := func(_ context.Context, server, _ string, _ uint16, transport string, _ time.Duration, _ uint16, _ bool, _ int) (dnsprobe.Attempt, *dns.Msg, *dns.Msg) {
		if server != "192.0.2.54:53" {
			t.Fatalf("query server=%s, want resolved glue-less nameserver IP", server)
		}
		return dnsprobe.Attempt{Transport: transport, Server: server, Success: true}, nil, childResponse
	}
	resolver := func(_ context.Context, name string) ([]string, error) {
		if name != "ck01.example.test." {
			t.Fatalf("resolver name=%s, want ck01.example.test.", name)
		}
		return []string{"192.0.2.54"}, nil
	}

	result := followReferrals(context.Background(), qname, dns.TypeA, config.Duration(time.Second), 1232, false, referral, query, resolver)
	if result.Assessment != "FOLLOWED" || len(result.Attempts) != 1 || result.Response != childResponse {
		t.Fatalf("unexpected referral result: %#v", result)
	}
}

func TestFollowReferralsDetectsLoop(t *testing.T) {
	qname := "highway.odot.state.or.us."
	referral := testReferral(qname, "ck01.example.test.", "192.0.2.53")
	query := func(_ context.Context, server, _ string, _ uint16, transport string, _ time.Duration, _ uint16, _ bool, _ int) (dnsprobe.Attempt, *dns.Msg, *dns.Msg) {
		return dnsprobe.Attempt{Transport: transport, Server: server, Success: true}, nil, referral
	}
	resolver := func(context.Context, string) ([]string, error) { return nil, nil }

	result := followReferrals(context.Background(), qname, dns.TypeA, config.Duration(time.Second), 1232, false, referral, query, resolver)
	if result.Assessment != "INCONCLUSIVE" || !strings.Contains(result.Error, "loop") {
		t.Fatalf("unexpected loop result: %#v", result)
	}
}

func testReferral(qname, nameserver, glueIP string) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(qname, dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeNS, Class: dns.ClassINET},
		Ns:  nameserver,
	}}
	if glueIP != "" {
		response.Extra = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: nameserver, Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP(glueIP),
		}}
	}
	return response
}

func testAResponse(qname, ip string) *dns.Msg {
	response := new(dns.Msg)
	query := new(dns.Msg)
	query.SetQuestion(qname, dns.TypeA)
	response.SetReply(query)
	response.Authoritative = true
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(ip),
	}}
	return response
}

func TestAssessExpectedAAAAAnswer(t *testing.T) {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	response.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2001:db8::10"),
	}}
	expected := config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"2001:db8::10"}}

	finding := assessExpectedAnswer(dns.TypeAAAA, expected, response)
	if finding.Status != "PASS" {
		t.Fatalf("AAAA expectation status=%s, want PASS: %s", finding.Status, finding.Detail)
	}
}

func TestAssessExpectedCNAMEAndTXTAnswers(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		qtype    uint16
		expected config.ExpectedAnswer
		answer   string
	}{
		{
			name:     "CNAME",
			qtype:    dns.TypeCNAME,
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{"target.example.test."}},
			answer:   "example.test. 300 IN CNAME Target.Example.Test.",
		},
		{
			name:     "TXT",
			qtype:    dns.TypeTXT,
			expected: config.ExpectedAnswer{RCode: "NOERROR", Answers: []string{`["v=spf1 -all"]`}},
			answer:   `example.test. 300 IN TXT "v=spf1 -all"`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := new(dns.Msg)
			response.Rcode = dns.RcodeSuccess
			rr, err := dns.NewRR(testCase.answer)
			if err != nil {
				t.Fatal(err)
			}
			response.Answer = []dns.RR{rr}
			finding := assessExpectedAnswer(testCase.qtype, testCase.expected, response)
			if finding.Status != "PASS" {
				t.Fatalf("expected answer status=%s, want PASS: %s", finding.Status, finding.Detail)
			}
		})
	}
}

func TestQueryNameForType(t *testing.T) {
	for _, testCase := range []struct {
		qtype uint16
		want  string
	}{
		{qtype: dns.TypeSOA, want: "example.test."},
		{qtype: dns.TypeNS, want: "example.test."},
		{qtype: dns.TypeA, want: "www.example.test."},
		{qtype: dns.TypeCNAME, want: "www.example.test."},
		{qtype: dns.TypeTXT, want: "www.example.test."},
	} {
		if got := queryNameForType("example.test.", "www.example.test", testCase.qtype); got != testCase.want {
			t.Errorf("queryNameForType(%s)=%q, want %q", dns.TypeToString[testCase.qtype], got, testCase.want)
		}
	}
}

func startFallbackTestServer(t *testing.T, truncateUDP bool) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", packetConn.LocalAddr().String())
	if err != nil {
		_ = packetConn.Close()
		t.Fatal(err)
	}

	var udpQueries, tcpQueries atomic.Int32
	udpServer := &dns.Server{
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			udpQueries.Add(1)
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.Truncated = truncateUDP
			if !truncateUDP {
				response.Answer = []dns.RR{testARecord()}
			}
			_ = writer.WriteMsg(response)
		}),
	}
	tcpServer := &dns.Server{
		Listener: tcpListener,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			tcpQueries.Add(1)
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.Answer = []dns.RR{testARecord()}
			_ = writer.WriteMsg(response)
		}),
	}
	udpDone := make(chan struct{})
	tcpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		_ = udpServer.ActivateAndServe()
	}()
	go func() {
		defer close(tcpDone)
		_ = tcpServer.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = packetConn.Close()
		_ = tcpListener.Close()
		<-udpDone
		<-tcpDone
	})

	return packetConn.LocalAddr().String(), &udpQueries, &tcpQueries
}

func testARecord() dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 1),
	}
}

func soaResponse(t *testing.T, serial uint32) *dns.Msg {
	t.Helper()
	soa, err := dns.NewRR("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. " +
		strconv.FormatUint(uint64(serial), 10) + " 3600 600 86400 300")
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	response.Answer = []dns.RR{soa}
	return response
}
