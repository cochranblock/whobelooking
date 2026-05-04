---
name: whobelooking-scan
description: Run a free attack-surface scan against a public URL via the whobelooking API. Probes ~80 paths (.env, configs, admin panels, leaked artifacts) and returns structured findings. Trigger when the user says "scan example.com", asks "what's exposed on X", or wants quick triage of a target.
---

# whobelooking-scan — surface-area scan via /api/scan/run

Calls whobelooking's free server-side scan API and reports findings grouped by severity.

## When to use

- Quick external attack-surface check against a domain.
- Triage step before deeper recon.
- Pre-engagement reachability check (also tells you if the target resolves).

## Endpoint

Production: `https://whobelooking.cochranblock.org/api/scan/run`
Local dev:  `http://localhost:8082/api/scan/run` (when running `cargo run --features serve`)

Override with `WHOBELOOKING_URL` env var.

## How to call

```bash
curl -sS -X POST "${WHOBELOOKING_URL:-https://whobelooking.cochranblock.org}/api/scan/run" \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com","severity":"all"}'
```

Severity options: `"critical"`, `"high"` (= critical+high), `"all"` (default).

For probe inventory:

```bash
curl -sS "${WHOBELOOKING_URL:-https://whobelooking.cochranblock.org}/api/scan/probes"
```

## Response shape

```json
{
  "target": "https://example.com",
  "started_at": 1714838400,
  "elapsed_ms": 1820,
  "probes": [
    {"path":"/.env","label":".env","sev":"critical","status":404,"ms":120,"hit":false}
  ],
  "summary": {"total":80,"hits":3,"critical_hits":1,"reachable":true}
}
```

A "hit" = status 2xx (openly accessible) or 401/403 (auth-walled — server processed the path). The `kind` field disambiguates: `accessible` (real exposure), `wall` (auth/WAF), `redirect`, `missing`, `server_error`, `unreachable`.

## Reporting back

1. If `summary.reachable` is false → lead with: target was mostly unreachable from our network — DNS, TLS, or firewall blocking. Scan inconclusive.
2. Otherwise split hits by `kind`:
   - `kind=accessible` first — these are real exposures, weight by severity (critical → high → medium).
   - `kind=wall` second — note that a 403 on a sensitive path usually means the WAF is doing its job; only flag as concerning if the host is known to run that stack (e.g., 403 on `/wp-config.php` against a real WordPress site).
3. For each hit: severity, kind, path, status, label.
4. Close: `{hits} hits ({accessible} accessible / {wall} walled) / {total} probed / {critical_hits} critical · {elapsed_ms}ms`.

## Constraints

- Public hosts only — RFC1918, loopback, link-local, documentation IPs rejected (SSRF guard).
- Rate limit: 5 full scans per minute per source IP.
- Only run against domains the user owns or has authorization to test.
