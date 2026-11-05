# Authoritative DNS Monitor

Go-based authoritative DNS probe for `highway.odot.state.or.us`.

## Current behavior

- Discovers the closest enclosing SOA zone using the host's configured recursive resolver.
- Retrieves NS records and resolves their IPv4/IPv6 addresses.
- Sends direct DNS queries to each discovered authoritative nameserver address.
- Queries SOA and NS at the discovered zone apex; queries A and AAAA at the configured target hostname.
- Tests UDP and TCP independently.
- Retries failed UDP attempts according to `udp_retries`.
- Validates DNS responses against the original query: transaction ID, QR bit, opcode, question name/type/class, and AA bit for these in-zone authoritative queries.
- Records whether a DNS message was received separately from whether it passed validation.
- Captures SOA fields and compares serials across responding authoritative nameservers.
- If a UDP response is truncated (`TC=1`), ignores its record data, attempts TCP fallback, and records a separate fallback assessment.
- Compares UDP Answer/Authority RRsets with a complete TCP response for an RFC 2181 Section 9 finding; differences isolated to Additional data do not require TC.
- Looks up the runner's public IP and network metadata once per run using `https://ipconfig.io/json`; each target result includes `source_ip`, `source_region_name`, `source_city`, `source_asn`, and `source_asn_org`.
- Emits one JSON document to stdout.

## Retry and finding semantics

`udp_retries` is a monitor policy, not a DNS protocol requirement.

- `retry_assessment: INCONCLUSIVE`: the first UDP attempt succeeded, so retry behavior was not exercised.
- `retry_assessment: PASS`: the first UDP attempt failed and a later configured attempt succeeded.
- `retry_assessment: FAIL`: no valid UDP response arrived within the configured attempt limit.
- `fallback_assessment: NOT_EXERCISED`: UDP did not return `TC=1`, so TCP fallback was not triggered.

A timeout is an availability observation. It is not automatically an RFC violation.

Findings use `PASS`, `FAIL`, `INCONCLUSIVE`, or `OBSERVED`. `OBSERVED` is used for behavior recorded without claiming a complete compliance determination.

## Current limitations

- Discovery relies on the machine's recursive resolver. Discovery is not itself an authoritative measurement.
- Truncation fallback is opportunistic: it runs when a normal UDP query returns `TC=1`. The RRset comparison can be inconclusive when data changes between UDP and TCP queries; it does not generate an oversized query against production zones.
- Source network details are observed by the HTTPS endpoint and may differ from the source address seen by authoritative DNS servers if HTTPS and DNS use different network routes or egress policies. Lookup failures are included as `source_ip_lookup_error` and do not stop DNS probes.
- The engine does not yet perform DNSSEC validation, a dedicated EDNS matrix, negative-answer/NXDOMAIN/NODATA tests, or full RFC compliance scoring.
- SOA consistency currently compares serials returned during the same run. It does not establish replication timing or whether a serial difference is acceptable during a zone transfer.
- IPv6 nameserver addresses may not be reachable from every Azure network configuration.
- Do not treat an absent AA bit as a universal failure for all DNS response types. The current checks are specifically for direct queries expected to be answered authoritatively by the discovered zone's nameservers.

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