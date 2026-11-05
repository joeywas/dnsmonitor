package monitoring

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

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
