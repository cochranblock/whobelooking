# Proof of Artifacts — whobelooking

All Rights Reserved — The Cochran Block, LLC

Every claim below is verifiable via the listed evidence.

## What This Does

You give yourself traffic data (Cloudflare logs, access logs, CSV). The tool tells you which companies are silently evaluating your site, which pages they read, how long they stayed, and whether they're a threat or an opportunity.

Real example: cochranblock.org caught Microsoft evaluating it across 14 IPs and 4 network ranges over 8 consecutive days. They downloaded the resume 5 times. The initial discovery traced to a LinkedIn post — same hour, same page, zero lag. Total marketing spend: $0.

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

### Demo / Try-It

→ **[whobelooking.cochranblock.org/try](https://whobelooking.cochranblock.org/try)** — drop an access log, get the demo experience on your own data. Parsing, rDNS, RDAP whois, classification, and rendering all run in your browser. **Nothing uploads.** Zero server-side data handling.

Formats supported: whobelooking-native, nginx combined, apache combined, Cloudflare Logpush CSV/JSONL.

## Modules

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

## CLI Commands

```
whobelooking serve              # start web server
whobelooking queue              # list all jobs
whobelooking pop                # take next pending job
whobelooking done {id}          # mark complete
whobelooking deliver {id}       # mark delivered
whobelooking report ...         # run enrichment pipeline
whobelooking scout ...          # federal contract search
```

Queue capacity: 12 hours/week. Jobs queued in sled. Manual review until AI analysis passes creator certification.

## Build

```
cargo build --features serve                          # with web server
cargo build --profile diamond --features serve        # production
cargo run --bin whobelooking-test --features tests,serve  # CI gate
```

Features: `serve` (axum web), `browser` (headless Chrome), `tests` (Triple Sims).

## Deploy

Gemini Man pattern — copy binary, run it, old process dies automatically via PID lockfile.

```
whobelooking serve --port 8082
```

Registers with approuter. Cloudflare tunnel routes traffic. DNS: whobelooking.org + whobelooking.com.

## Binary

| Artifact | Evidence |
|----------|----------|
| Diamond binary | `target/diamond/whobelooking` — 6.6MB, opt-level 3, fat LTO, codegen-units 1, stripped, panic=abort |
| Single binary | One file serves: web frontend, CLI, queue management, CF pull, rDNS, /24 scan, federal scout, CTO OSINT |
| Zero cloud | No AWS, no Docker, no Kubernetes, no external database. sled embedded KV + filesystem folders. |
| Gemini Man | PID lockfile at ~/.local/share/whobelooking/pid — SIGTERM → 5s wait → SIGKILL fallback |

## Live Deployment

| Artifact | Evidence |
|----------|----------|
| whobelooking.org | Live at https://whobelooking.org — 200 OK, auto-playing demo |
| whobelooking.com | Resolves to same infrastructure |
| Registered in approuter | `curl localhost:8080/approuter/apps` shows whobelooking entry |
| Cloudflare tunnel | DNS CNAME → cfargotunnel.com → approuter → whobelooking:8082 |
| Stripe Checkout | Test keys loaded. POST /order/checkout creates Stripe session. |

## Tests

| Artifact | Evidence |
|----------|----------|
| Test binary | `cargo run --bin whobelooking-test --features tests,serve` |
| 66 unit tests | OSINT (28), queue (6), web content (6), security (2), theme (4), demo structure (6), content integrity (6), legal (2), order flow (6) |
| Triple Sims | exopack f60 — 3 passes, all must produce identical results |
| 14-point standards gate | exopack standards_check::f101 — 10/14 passing |
| Zero clippy warnings | `cargo clippy --features serve` clean (including pedantic scan) |
| #![forbid(unsafe_code)] | lib.rs line 2 |

## Web Frontend / Routes

| Artifact | Evidence |
|----------|----------|
| Demo page (/) | Interactive ops center auto-playing real cochranblock.org visitor data |
| Marketing page (/about) | Pricing, enrichment flywheel, capacity meter, terminal animation |
| Order form (/order) | 4-tier grid selector, Stripe Checkout redirect, form validation |
| Queue status (/queue) | Live capacity display from filesystem folder count |
| Admin dashboard (/admin) | Token-gated, shows pending/approved/rejected/ready folders |
| Download endpoint (/download/{id}) | Dynamic from ready/ folder, Stripe payment verification |
| Confirmation page (/order/confirmed) | Shows queue position, order reference |
| Health check (/health) | Returns "ok" |
| robots.txt | Welcomes GPTBot, ChatGPT-User, Google-Extended, Applebot-Extended, anthropic-ai |
| 404 handler | Returns 404 status code (not 200) |

## AI-Readable Metadata

| Artifact | Evidence |
|----------|----------|
| JSON-LD SoftwareApplication | 4 pricing offers (Starter $150, Growth $350, Scale $750, Custom $1,500+) |
| JSON-LD FAQPage | 8 questions covering what/how/cost/flywheel/threats/sources/reviewer/KNOXAI |
| JSON-LD Organization | The Cochran Block, LLC with founder, address, sameAs links |
| Open Graph tags | og:title, og:description, og:url, og:site_name |
| Twitter Card | summary_large_image |

## Security

| Artifact | Evidence |
|----------|----------|
| IP redaction | All IPs in demo/marketing redacted to first two octets (x.x). Test enforces no full IPv4 in demo.html. |
| No secrets in output | Test scans demo for CF_TOKEN, STRIPE_KEY, API_KEY, kovakey, id_ed25519 |
| No internal paths | Test scans demo for /Users/mcochran, /home/mcochran, ~/.ssh, ~/.secrets |
| Stripe payment verification | /download/{id} verifies session_id against Stripe API (payment_status == "paid") |
| 404 status codes | Fallback handler returns HTTP 404, not 200 with error page |
| Admin token gate | /admin requires ADMIN_TOKEN query parameter |
| Attacker blocked | 88.151.32.0/24 (NextGenWebs Spain) blocked at Cloudflare edge |

## Filesystem Queue

| Artifact | Evidence |
|----------|----------|
| pending/ | Orders land here. Max 5. Each order is a directory with order.txt |
| approved/ | You move orders here after review |
| rejected/ | Rejected orders go here |
| ready/ | Drop {id}.pdf here → /download/{id} endpoint exists. Remove → endpoint dies. |
| order.txt format | id, email, site, source, tier, created (epoch seconds) |

## Dependencies (Cargo.toml)

| Crate | Purpose | License |
|-------|---------|---------|
| clap 4 | CLI parser | MIT/Apache-2.0 |
| reqwest 0.12 | HTTP client (rustls) | MIT/Apache-2.0 |
| serde + serde_json | Serialization | MIT/Apache-2.0 |
| tokio 1 | Async runtime | MIT |
| anyhow 1 | Error handling | MIT/Apache-2.0 |
| hickory-resolver 0.25 | DNS resolution | MIT/Apache-2.0 |
| sled 0.34 | Embedded KV store | MIT/Apache-2.0 |
| dirs 5 | Standard directories | MIT/Apache-2.0 |
| zstd 0.13 | Compression | MIT |
| uuid 1 | UUID generation | MIT/Apache-2.0 |
| axum 0.8 [serve] | Web framework | MIT |
| tower-http 0.6 [serve] | HTTP middleware | MIT |
| tracing + tracing-subscriber | Structured logging | MIT |
| exopack [tests] | Triple Sims + standards gate | All Rights Reserved |
| regex-lite [tests] | IP redaction test | MIT/Apache-2.0 |

## Protocols Applied

| Protocol | Application |
|----------|-------------|
| P16 | CI = test binary. `whobelooking-test` is the quality gate. 5 stages. |
| P26 | Moonshot Frame. Every commit tagged [P26] was reviewed against civilizational-scale standard. |
| P27 | Diamond Rust Binary. 6.6MB production binary. speed-diamond profile. |
| Gemini Man | PID lockfile hot reload. No systemd. Copy binary, run it, old dies. |
| Assumed Breach | Enrichment cache is shared (universal). Customer data is private (per-order). Stripe keys in env, not code. |

## Commit History

```
git log --oneline | wc -l  →  commits since inception
git log --format="%ai" | head -1  →  latest commit
git log --format="%ai" | tail -1  →  first commit
```

All commits signed by `KOVA (AI)` with `Co-Authored-By: Claude Opus 4.6`.
<!-- COCHRANBLOCK-BRAND-FOOTER:START - generated by cochranblock/scripts/brand-stamp.sh -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
