# whobelooking

Visitor intelligence platform. Any IP source → rDNS → /24 scan → whois → company ID → enrichment flywheel → intelligence report.

**One binary. Zero cloud. All Rights Reserved.**

## What This Does

You give us traffic data (Cloudflare credentials, access logs, CSV). We tell you which companies are silently evaluating your site, which pages they read, how long they stayed, and whether they're a threat or an opportunity.

Real example: We caught Microsoft evaluating cochranblock.org across 14 IPs and 4 network ranges over 8 consecutive days. They downloaded the resume 5 times. We traced the initial discovery to a LinkedIn post — same hour, same page, zero lag. Total marketing spend: $0.

## Architecture

```
INPUT (any source)          PIPELINE                        OUTPUT
─────────────────          ──────────                       ──────
Cloudflare API  ─┐
Access logs     ─┤         IP + path + timestamp
CSV / JSON      ─┘─────►  → rDNS batch                     PDF report
                           → /24 neighbor scan               + threat alerts
                           → RDAP whois                      + confidence gauges
                           → company identification          + recommendations
                           → sled enrichment cache
                           → manual review by operator
```

### The Enrichment Flywheel

Every report caches rDNS, whois, and company ID results in sled. Customer #1's Microsoft identification helps Customer #50's report resolve instantly. The more sites in the system, the better every report gets. The data compounds. That's the moat.

Cache key structure:
- `enrich:rdns:{ip}` → hostname
- `enrich:whois:{/24}` → org, city, state, country
- `enrich:company:{/24}` → company name + confidence
- `enrich:neighbor:{/24}` → interesting PTR records

### Modules

| Module | Purpose |
|--------|---------|
| `cf` | Cloudflare GraphQL pull → visitor IPs |
| `dns` | rDNS batch + /24 neighbor scanning |
| `report` | Full pipeline: pull → rDNS → scan → output |
| `scout` | Federal contract intelligence (8 APIs) |
| `queue` | sled-backed job queue, 12hr/week capacity |
| `web` | axum server at whobelooking.org |
| `web::checkout` | Stripe Checkout integration |
| `browse` | Headless Chrome (screenshots, perf, scrape) |
| `ctos` | CTO OSINT (HN, GitHub, Reddit, YC, Podcasts) |

### Queue System

Capacity: 12 hours/week. Jobs queued in sled. Manual review until AI analysis passes creator certification.

```
whobelooking serve              # start web server
whobelooking queue              # list all jobs
whobelooking pop                # take next pending job
whobelooking done {id}          # mark complete
whobelooking deliver {id}       # mark delivered
whobelooking report ...         # run enrichment pipeline
whobelooking scout ...          # federal contract search
```

### Pricing

| Tier | Unique IPs | Hours | Price |
|------|-----------|-------|-------|
| Starter | <500 | ~1.5h | $150 |
| Growth | 500-2K | ~3h | $350 |
| Scale | 2K-10K | ~6h | $750 |
| Custom | 10K+ | ~8h | $1,500+ |

## Build

```
cargo build --features serve              # with web server
cargo build --profile diamond --features serve  # production
cargo run --bin whobelooking-test --features tests,serve  # CI gate
```

Features: `serve` (axum web), `browser` (headless Chrome), `tests` (Triple Sims).

## Deploy

Gemini Man pattern — copy binary, run it, old process dies automatically via PID lockfile.

```
whobelooking serve --port 8082
```

Registers with approuter. Cloudflare tunnel routes traffic. DNS: whobelooking.org + whobelooking.com.

## Tests

60 tests. Triple Sims (3 passes, all must match). Categories:
- OSINT pipeline (28): text parsing, cross-verification, email filtering
- Queue system (6): capacity math, serialization, source types
- Web content (6): demo contains expected companies, no full IPs
- Theme (4): cosmic palette enforced, no stale Monokai
- Demo structure (6): feed, timeline, stats, enrichment, roster, autoplay
- Content integrity (6): all companies present, attacker story complete
- Security (2): no secrets, no internal paths
- Legal (2): All Rights Reserved, no Unlicense

## Protocols

- P16: CI = test binary. `whobelooking-test` is the quality gate.
- P26: Moonshot Frame. Would this hold up at civilization scale?
- P27: Diamond Rust Binary. 6.6MB production binary.
- Gemini Man: PID lockfile hot reload. No systemd.
- Assumed Breach: enrichment cache is shared, customer data is private.

## Legal

All Rights Reserved — The Cochran Block, LLC
CAGE 1CQ66 · UEI W7X3HAQL9CF9 · SDVOSB Pending

Contact: mcochran@cochranblock.org
Site: https://whobelooking.org
