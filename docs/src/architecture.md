# Architecture

## Pipeline

```
INPUT                      WASM PIPELINE                   OUTPUT
─────                      ─────────────                   ──────

Any log file               f400: format detect
  nginx                    f401–f435: parse per format
  CF NDJSON         ──►    f460–f470: aggregate per-IP  ──► Standalone HTML report
  AWS ALB                  f460–f470: 4-class classify       (cyberpunk dark theme)
  pcap                     f440–f453: render
  (17 formats)

Cloudflare API             server-side only
  GraphQL           ──►    rDNS batch (hickory)          ──► intel.unredacted.html
  httpRequestsAdaptive     RDAP WHOIS (redb cache)           intel.redacted.html
  firewallEvents           org identification
```

## Two Execution Contexts

The same `wbl-detect` crate compiles to two targets:

| Context | How it runs | Used by |
|---------|-------------|---------|
| `wasm32-unknown-unknown` | In the browser, ~219 KB | `/try`, `/scan`, `/detect` |
| `x86_64-unknown-linux-gnu` | Server binary | `whobelooking render`, `whobelooking intel` |

The WASM build uses `json_lite` instead of `serde_json` to save ~30 KB.

## Classification

Four classes in a strict priority lattice (threat beats everything):

| Class | What it means | Example signals |
|-------|--------------|-----------------|
| `THREAT` | Active scanning or exploitation | `/wp-admin/install.php`, `/.env`, `/aws/credentials` |
| `INSTITUTIONAL` | Corporate / government research | Reverse PTR resolves to company domain, low-noise paths |
| `ORGANIC` | Human visitor, non-institutional | Browser UA, normal path distribution |
| `BOT` | Crawler or automated traffic | `Googlebot`, `curl`, monitoring agents |

`THREAT` overrides any other class. A session with one threat probe and 50 organic hits is `THREAT`.

## Enrichment Flywheel

All rDNS and RDAP results are cached in a `redb` embedded key-value store. Every new query benefits from prior lookups across all sites using the same instance. The data compounds: the more sites feeding the system, the faster and richer every future report becomes.

Cache namespaces: `visits`, `orders`, `queue`, `scout`, `rdap`, `cto`, `enrichment`.

## Server

Built on `axum` 0.8 behind the `serve` feature flag. The binary stays minimal without it.

Key routes:

| Route | Description |
|-------|-------------|
| `GET /` | Landing page with live demo |
| `GET /try` | WASM log analyzer |
| `GET /detect` | WASM column-type detector |
| `GET /scan` | WASM surface scanner (140+ probes) |
| `GET /api/cf/pull` | CF Analytics GraphQL proxy → NDJSON |
| `GET /api/probe` | Single-path probe (SSRF-guarded, rate-limited) |
| `GET /health` | `200 ok` |
| `GET /metrics` | Prometheus (requires `ADMIN_TOKEN`) |

## Security Invariants

- `#![forbid(unsafe_code)]` on all crate members
- SSRF guard: private/loopback IPs rejected before any outbound probe call
- Rate limiting on `/api/probe`: 7,500 req/min per source IP, in-memory bucket
- No secrets in demo output (tested: CF_TOKEN, STRIPE_KEY, API_KEY, id_ed25519)
- Admin/metrics routes gated by `ADMIN_TOKEN`

## Gemini Man Pattern

The server uses `fd-lock` for PID-file locking during hot reload. On `SIGTERM`, the old process serializes in-memory state to a compressed snapshot (`~/.local/share/whobelooking/logs/`), and the new process restores from it. Visit counters are continuous across restarts.

## Build Profiles

| Profile | Use case | Flags |
|---------|----------|-------|
| `dev` | Development | unoptimized, debug info |
| `release` | Default release | `opt-level=z`, LTO, `codegen-units=1`, stripped |
| `diamond` | Server production | `opt-level=3`, fat LTO, stripped — runtime wins |
| `diamond-edge` | Edge / embedded | `opt-level=s`, fat LTO — bytes win |
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
