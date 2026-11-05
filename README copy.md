# Authoritative DNS Monitor (starter)

Go-based first-stage probe for `highway.odot.state.or.us`.

## What it does
- Discovers the closest SOA zone using the host's configured recursive resolver.
- Retrieves NS records and resolves nameserver addresses.
- Sends direct UDP and TCP DNS queries to each discovered authoritative IP.
- Records attempt timestamps, latency, DNS flags, RCODE, and section counts.
- Emits one JSON document to stdout.

## Important limitations of this starter
- Discovery currently relies on the machine's recursive resolver. Discovery is not itself an authoritative measurement.
- The first implementation performs baseline UDP/TCP checks and basic truncation observation. It does not yet synthesize a guaranteed oversized response, validate DNSSEC, or fully score RFC compliance.
- Retry count is a monitor policy (0-2 retries), not a claim that an authoritative server must implement resolver retry behavior.
- IPv6 targets are discovered but may not be reachable from every Azure network configuration.
- Do not treat an absent AA bit as a universal failure for every possible DNS response type; response semantics matter.

## Run locally
Requires Go 1.23+.

```bash
go mod tidy
go run ./cmd/probe -config configs/targets.yaml
```

## Container
```bash
docker build -t dns-monitor:dev .
docker run --rm dns-monitor:dev
```

## Next steps
1. Replace discovery with explicit iterative delegation tracing and glue handling.
2. Add a deterministic truncation fixture/test zone.
3. Add response validation against the original query for every attempt.
4. Add structured HTTPS telemetry to a Cloudflare Worker.
5. Add D1 schema, ingestion authentication, and dashboard.
6. Deploy as an Azure Container Apps Job on a 15-minute cron schedule.
