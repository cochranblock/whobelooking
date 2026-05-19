# whobelooking

Visitor intelligence platform. Any IP source → rDNS → /24 scan → whois → company ID → enrichment flywheel → intelligence report.

One binary. Zero cloud. Unlicense.

## What It Does

whobelooking takes an IP address and builds an intelligence report: reverse DNS lookup, /24 subnet scan, WHOIS enrichment, company identification. The enrichment flywheel stores results and cross-references future lookups against the accumulated dataset.

Deployed at cochranblock.org — every visitor to the site runs through the pipeline.

## Architecture

| Component | Description |
|-----------|-------------|
| `rDNS` | Reverse DNS resolution per IP |
| `/24 scanner` | Subnet sweep to find related hosts |
| `WHOIS` | Ownership and registration data |
| `enrichment store` | redb-backed persistent intelligence cache |
| `web server` | Axum — `GET /probe`, `GET /scan`, `POST /report` |
| `TUI` | Real-time intelligence dashboard |

## Build

```bash
cargo build --features serve                         # with web server
cargo build --profile diamond --features serve       # 6.6 MB production binary
whobelooking serve --port 8082
```
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
