# Log Formats

`wbl-detect` auto-detects the format of any input file. Drop it into `/try`, pass it to `whobelooking render`, or stream it through `whobelooking parse-logs` — no flags needed.

## Supported Formats

| Format | Auto-detect key | Notes |
|--------|----------------|-------|
| **whobelooking native** | `visit ip=` tracing lines | Internal server log format |
| **nginx / Apache Combined Log Format** | `"GET / HTTP/` structure | CLF + user-agent + referer |
| **Cloudflare NDJSON** | `ClientIP`, `EdgeStartTimestamp` | Analytics GraphQL export |
| **Cloudflare CSV** | CSV header with `ClientIP` | Logs tab bulk export |
| **OTEL / OpenTelemetry** | `logRecords[].attributes` | HTTP semantic conventions (stable + pre-1.21) |
| **Syslog RFC 3164 / RFC 5424** | `<PRI>` header | Unwraps inner HTTP log line and re-routes |
| **ELK / Logstash JSON** | `clientip`, `verb`, `request` fields | grok'd output; `message` fallback |
| **Splunk JSON / KV** | `_raw` field | JSON `_raw` or KV `_raw="..."` unwrap |
| **W3C Extended / IIS** | `#Fields:` header line | Standard W3C log format |
| **HAProxy** | `haproxy[` or `frontend`/`backend` | HTTP + TCP log formats |
| **AWS ALB / ELB** | space-delimited, `https?` type field | ALB access log format |
| **Azure Diagnostic JSON** | `callerIpAddress`, `clientIP`, `clientIp` | Activity Log, App Gateway, CDN |
| **GCP Cloud Logging** | `httpRequest.remoteIp` | Structured JSON log entries |
| **Generic JSON fallback** | any JSON with common IP field names | `ip`, `remote_addr`, `remote_ip`, `client_ip`, etc. — key-prefix scan at any nesting depth |
| **Binary pcap v2.4** | magic bytes `0xd4c3b2a1` / `0xa1b2c3d4` | LE/BE; Ethernet, raw IP, Linux SLL link types; IPv4 + IPv6; HTTP method/path/UA from TCP payload |
| **Hex dump text** | xxd / Wireshark / tcpdump / raw hex strings | Decoded to bytes → routed through pcap parser |
| **Raw IP extraction** | fallback on any unstructured file | ACAS/Nessus output, email headers, config dumps — octets validated 0–255 |

## Mixed Files

If a file contains multiple formats (e.g. a syslog stream that interleaves nginx lines and raw visit lines), `wbl-detect` routes each line independently and tags the result as `mixed`.

## Example: Drop Anything

```bash
# nginx
whobelooking render /var/log/nginx/access.log

# Cloudflare NDJSON from /api/cf/pull
whobelooking render cf-export.ndjson

# AWS ALB
whobelooking render alb_access_log_2026-05-19.log

# pcap
whobelooking render capture.pcap

# Wireshark hex export
whobelooking render dump.txt

# Splunk JSON export
whobelooking render splunk_search.json

# GCP Cloud Logging export
whobelooking render gcp_logs.json
```

All of these produce the same output: a standalone HTML intelligence report.
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
