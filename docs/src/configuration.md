# Configuration

## Server

| Env Var | Default | Description |
|---------|---------|-------------|
| `WBL_PORT` | `8082` | Port for `whobelooking serve` |
| `CF_TOKEN` | — | Cloudflare API token (used by `cf-fleet`, `cf-enrich`, `intel`, `/api/cf/pull`) |
| `ADMIN_TOKEN` | — | Token required for `/admin` and `/metrics` routes |

## Airgap Mode {#airgap}

`/try` and `/scan` make outbound calls for DoH PTR resolution, RDAP WHOIS, font loading, and enrichment snapshots. On isolated networks, override each with an internal endpoint:

| Env Var | Default | Description |
|---------|---------|-------------|
| `WBL_DOH_URL` | Cloudflare DoH | DoH resolver endpoint for PTR lookups in `/try` |
| `WBL_RDAP_BASE` | `https://rdap.org` | RDAP WHOIS base URL |
| `WBL_ENRICHMENT_URL` | `/api/enrichment.json` | Enrichment snapshot endpoint |
| `WBL_FONTS_HREF` | Google Fonts URL | CSS font stylesheet — set empty to drop the link entirely |
| `WBL_AIRGAP_NOTICE` | (none) | Banner text shown in `/try` for isolated networks |

The CSP `connect-src` header is computed per-request from these values. There is no hardcoded cross-origin fallback — if you set `WBL_DOH_URL`, that's the only DoH host the browser is allowed to contact.

## OpenTelemetry

OTEL instrumentation is behind the `otel` feature flag and configures entirely via standard OTEL env vars:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_SERVICE_NAME=whobelooking
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production
```

Build with OTEL support:

```bash
cargo build --features serve,otel
```

Instruments: `wbl.scan.*` (surface scanner) and `wbl.enrichment.*` (RDAP cache).

## Logging

Uses `tracing` + `tracing-subscriber`. Control level with:

```bash
RUST_LOG=whobelooking=debug whobelooking serve
```

Log files are written to `~/.local/share/whobelooking/logs/` with daily rotation.
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
