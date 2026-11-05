# Authoritative DNS Monitor

Go-based authoritative DNS probe for `highway.odot.state.or.us`.

## Current behavior

- Discovers the closest enclosing SOA zone using the host's configured recursive resolver.
- Retrieves NS records and resolves their IPv4/IPv6 addresses.
- Sends direct DNS queries to each discovered authoritative nameserver address.
- Queries SOA and NS at the discovered zone apex; queries address, alias, and text records at the configured target hostname.
- Tests UDP and TCP independently.
- Retries failed UDP attempts according to `udp_retries`.
- Validates DNS responses against the original query: transaction ID, QR bit, opcode, question name/type/class, and AA bit for these in-zone authoritative queries.
- Records whether a DNS message was received separately from whether it passed validation.
- Captures SOA fields and compares serials across responding authoritative nameservers.
- If a UDP response is truncated (`TC=1`), ignores its record data, attempts TCP fallback, and records a separate fallback assessment.
- Compares UDP Answer/Authority RRsets with a complete TCP response for an RFC 2181 Section 9 finding; differences isolated to Additional data do not require TC.
- Looks up the runner's public IP and network metadata once per run using `https://ipconfig.io/json`; each target result includes `source_ip`, `source_region_name`, `source_city`, `source_asn`, and `source_asn_org`.
- Optionally checks configured expected A/AAAA/CNAME/TXT RCODEs and answer sets against the UDP response, the TCP fallback when UDP is truncated, and reports a separate expected-answer assessment for the independent TCP baseline.
- Includes received Answer, Authority, and Additional RRs in each attempt's `answer_records`, `authority_records`, and `additional_records` fields for diagnosis.
- Emits one JSON document to stdout.

## Retry and finding semantics

`udp_retries` is a monitor policy, not a DNS protocol requirement.

- `retry_assessment: INCONCLUSIVE`: the first UDP attempt succeeded, so retry behavior was not exercised.
- `retry_assessment: PASS`: the first UDP attempt failed and a later configured attempt succeeded.
- `retry_assessment: FAIL`: no valid UDP response arrived within the configured attempt limit.
- `fallback_assessment: NOT_EXERCISED`: UDP did not return `TC=1`, so TCP fallback was not triggered.
- `expected_answer_assessment: NOT_CONFIGURED`: no expected answer was configured for that record type.
- `expected_answer_assessment` is the UDP (or truncation-fallback) result; `expected_answer_tcp_assessment` is the independent TCP baseline and does not override the UDP result.
- Configured expected-answer probes follow empty-answer NS referrals over UDP, using glue when present or the system resolver to find nameserver addresses. Referral chasing is limited to five hops with loop detection; the chain and all hop attempts are recorded. Unresolved or looping referrals are inconclusive/failures rather than being mistaken for final NODATA.
- `referral_assessment` is `NOT_NEEDED` when no referral was returned, `FOLLOWED` when a referral chain reached a non-referral response, `FAILED` when delegated nameservers could not be resolved or queried, or `INCONCLUSIVE` when a loop or hop limit stops chasing.
- Each attempt includes an `outcome`: DNS RCODE category, `TRUNCATED`, `TIMEOUT`, `TRANSPORT_ERROR`, `INVALID_RESPONSE`, `EMPTY_RESPONSE`, or `CANCELED`. `success` continues to mean a valid DNS message passed response validation; it does not mean the requested data was returned.
- `NXDOMAIN` is a valid DNS negative response and is reported as `OBSERVED`; `REFUSED`, `SERVFAIL`, and other error RCODEs are reported as unsuccessful query outcomes.

A timeout is an availability observation. It is not automatically an RFC violation.

Findings use `PASS`, `FAIL`, `INCONCLUSIVE`, or `OBSERVED`. `OBSERVED` is used for behavior recorded without claiming a complete compliance determination.

Expected answers are optional and support A/AAAA addresses, CNAME targets, and TXT RDATA. `answers: []` explicitly expects no records for that type. A/AAAA values are IP addresses; CNAME values are target names; TXT values use DNS master-file quoting. Only configure values confirmed to be stable and correct for the protected DNS service.

```yaml
expected_answers:
	A:
		rcode: NOERROR
		answers: ["159.121.71.106"]
	CNAME:
		rcode: NOERROR
		answers: ["target.example.test."]
	TXT:
		rcode: NOERROR
		answers: ['"v=spf1 -all"']
	AAAA:
		rcode: NOERROR
		answers: []
```

  A:
    rcode: NOERROR
    answers: ["159.121.71.106"]
  CNAME:
    rcode: NOERROR
    answers: ["target.example.test."]
  TXT:
    rcode: NOERROR
    answers: ['"v=spf1 -all"']

## Run locally

Requires Go 1.23+.

```bash
go mod tidy
go test ./...
go run ./cmd/probe -config configs/targets.yaml
```

The configured `interval` is the intended monitoring cadence; this executable performs one probe run. Scheduling will be handled by the Azure job configuration later.

## Container

```bash
docker build -t dns-monitor:dev .
docker run --rm dns-monitor:dev
```

## Next engineering steps

1. Add a deterministic truncation test using a controlled test zone or fixture.
2. Add negative-answer, EDNS(0), and DNSSEC-specific probes.
3. Improve discovery with iterative delegation tracing and glue handling.
4. Add structured HTTPS telemetry to a Cloudflare Worker.
5. Add D1 schema, ingestion authentication, and dashboard.
6. Deploy as an Azure Container Apps Job on a 15-minute cron schedule.

## To zip things up

```bash
zip -r toagent.zip . -x "LICENSE" -x "results.json"
```

## Helpful dig commands

```bash
dig @198.232.202.40 highway.odot.state.or.us A +norecurse +tcp +bufsize=1232 +time=5 +tries=1 +noall +comments +answer +authority +additional

dig @198.232.200.20 highway.odot.state.or.us A +norecurse +tcp +bufsize=1232 +time=5 +tries=1 +noall +comments +answer +authority +additional

dig highway.odot.state.or.us A +time=3 +tries=1
```
