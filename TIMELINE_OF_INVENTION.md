# Timeline of Invention — whobelooking

All Rights Reserved — The Cochran Block, LLC
Append-only. Each entry timestamped by git commit. Do not edit prior entries.

| Date | Commit | Event |
|------|--------|-------|
| 2026-04-07 | — | whobelooking v0.1.0 — Cloudflare GraphQL visitor pull + rDNS batch + /24 neighbor scanning |
| 2026-04-08 | 32575fa | Headless Chrome CDP integration — screenshots, perf benchmarking |
| 2026-04-08 | 66f3412 | Performance benchmark: FPS, CLS, paint timing, resource count via Chrome DevTools Protocol |
| 2026-04-08 | 4dc2607 | 8 federal API integrations: SAM.gov, USASpending, SBIR, Federal Register, Grants.gov, Contract Awards, Regulations.gov, GSA CALC+ |
| 2026-04-09 | — | sled caching with zstd compression + dedup across all 8 sources |
| 2026-04-10 | 0dbdba2 | CTO OSINT pipeline: HN Algolia, GitHub user search, Reddit, YC (headless), Podcasts (headless). Cross-verification across 2+ sources. Email extraction with domain correlation. Draft generation. |
| 2026-04-21 | — | Live deployment: caught Microsoft (14 IPs, 4 network ranges, 8 days), Google VPN (4 visits, 3 days), IBM (392 hits, 6 days), Two Six Technologies (5 Ashburn IPs), Brisbane/Domino's ANZ CISO |
| 2026-04-21 | — | Blocked NextGenWebs Spain attacker (88.151.x.x) probing .aws/credentials, .cursor/mcp.json, .env — detected, identified, /24 blocked at CF edge in 10 minutes |
| 2026-04-22 | d506ff5 | v0.2.0 — web frontend (axum), sled-backed queue, All Rights Reserved |
| 2026-04-22 | 9a4fa7f | CI gate: 34 tests, exopack Triple Sims, queue system tests |
| 2026-04-22 | d266378 | Ripped out 4 ice cream cone tests. 42 real tests. IP redaction test caught leak (88.151.32.0). |
| 2026-04-22 | 5eb7526 | Interactive ops center demo — auto-plays real cochranblock.org story (8 days, Microsoft → attacker → resume download) |
| 2026-04-22 | 37cebe3 | Cosmic theme: cochranblock palette (#050508 void, #00d9ff cyan, #9d4edd purple, #00ffcc teal). Orbitron + Rajdhani fonts. Portrait/landscape queries. |
| 2026-04-22 | 478ff80 | Stripe Checkout integration — order form with 4-tier grid selection |
| 2026-04-22 | d9da014 | Gemini Man pattern — PID lockfile hot reload, graceful shutdown |
| 2026-04-22 | ad52f64 | AI-readable metadata: JSON-LD (SoftwareApplication, FAQPage, Organization), Open Graph, robots.txt welcoming GPTBot/ChatGPT-User/Google-Extended/anthropic-ai |
| 2026-04-22 | a655968 | Filesystem queue: pending/approved/rejected/ready folders, 5 max capacity, no database |
| 2026-04-22 | 2895cb5 | Dynamic download endpoints: drop PDF in ready/{id}.pdf → /download/{id} exists. Remove PDF → endpoint dies. |
| 2026-04-22 | e8ea8ac | Payment flow: free submit, pay at download. Order creates folder, payment happens when report is ready. |
| 2026-04-22 | 14a9c47 | Security: Stripe session_id verification — checks payment_status == "paid" via Stripe API before serving PDF. No ?paid=1 bypass. |
| 2026-04-22 | 3ee9cdf | 66 tests: order flow, capacity limits, admin auth, download security, filesystem queue |
| 2026-04-22 | 5fff9f8 | 14-point exopack standards gate: #![forbid(unsafe_code)], rust-version, TIMELINE_OF_INVENTION.md, LICENSE, cargo fmt |
| 2026-04-22 | 0393b72 | Zero clippy warnings (pedantic scan clean). 66 tests, Triple Sims 3/3, 10/14 standards. |
| 2026-04-22 | — | whobelooking.org + whobelooking.com live. Diamond binary 6.6MB. Registered in approuter. Stripe test keys loaded. |
| 2026-05-06 | 7fbfe61 | Server-side `/api/scan/run` — fan-out probe of ~80 attack-surface paths, JSON/CSV output, Swagger UI + Claude skill + email delivery |
| 2026-05-09 | 63e9e26 | Free / Unlicense pivot complete in user-facing copy. Order flow removed in favor of self-serve. |
| 2026-05-15 | — | v0.3.0 — WASM-driven `/try` page: drop a log → in-browser parse + DoH PTR + RDAP + classify + standalone HTML report download. JS reduced to thin glue around the `wbl-detect` engine; HTML is the deliverable. `/api/scan/run?format=html` joins JSON/CSV outputs. |
| 2026-05-15 | — | wbl-detect v0.2.0 — new modules: `parse` (5 log formats), `aggregate` (per-IP rollup + 4-class lattice), `report` (cyberpunk standalone HTML), `json_lite` (replaces `serde_json` to save ~30 KB WASM). |
| 2026-05-15 | — | Double-binary standard enforced via `exopack::deny_release_with_tests!()` tripwire — `cargo build --release --features tests` now fails at compile time. |
| 2026-05-16 | — | KOVA tokenization applied to `wbl-detect` public + internal surface (f400–f470, t100–t151). JS-facing names preserved via `#[wasm_bindgen(js_name = …)]`. 14/14 standards, 194 tests, TRIPLE SIMS 3/3. |
| 2026-05-16 | — | OTEL — server-side: `opentelemetry` 0.27 + `opentelemetry-otlp` behind `otel` feature; OTLP/gRPC trace + metric exporter; `wbl.scan.*` + `wbl.enrichment.*` instruments around `/api/scan/run` and the RDAP cache. Standard OTEL env-var config (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`). |
| 2026-05-16 | — | OTEL ingest — `wbl-detect::parse::f425` decodes OTLP/JSON logRecords into `t100` Events; supports both stable HTTP semantic conventions (`client.address`, `http.request.method`, `user_agent.original`) and pre-1.21 (`net.peer.ip`, `http.method`, `http.user_agent`). New `t101::Otel` format variant. |
| 2026-05-16 | — | Airgap mode — `/try` endpoints now env-driven for isolated networks: `WBL_DOH_URL`, `WBL_RDAP_BASE`, `WBL_ENRICHMENT_URL`, `WBL_FONTS_HREF`, `WBL_AIRGAP_NOTICE`. CSP `connect-src` computed per-request from the configured hosts; no blanket-allow. Template substitution in `try_page.rs`. |
| 2026-05-16 | — | Government / SIEM log format ingest: syslog RFC 3164 + RFC 5424 (unwrap priority + metadata, route inner content through existing parsers); ELK / Logstash JSON (grok'd `clientip`/`verb`/`request` fields or `message` fallback); Splunk JSON `_raw` + KV `_raw="..."` unwrap. 227 tests, 14/14 standards. WASM 219 KB. |
| 2026-05-17 | — | Remove server-side `/api/scan/run` batch endpoint (and `/api/scan/probes`, `/api/scan/email`). Scanning is now entirely WASM-driven in the browser; WASM calls `/api/probe` as a local proxy — works on airgapped networks, no public batch endpoint. 910 lines removed. |
| 2026-05-17 | — | W3C Extended log format, IIS, and HAProxy parsers added to `wbl-detect`. Raw IP extraction fallback (`f435`): any unstructured file (ACAS/Nessus output, email headers, config dumps) dropped into the browser or CLI has IPs regex-extracted and enriched. `render` CLI command: log file → rDNS-enriched standalone HTML report. 241 tests, triple sims 3/3, 14/14 standards. |
| 2026-05-18 | — | End-to-end smoke test stage added to `whobelooking-test` (Stage 5): hits running server at `localhost:8082` (or `WBL_SMOKE_URL`), tests `/health`, `/try` CF panel, and `/api/cf/pull` validation. Skips gracefully when server is down; fails the gate when reachable. 269 unit tests + smoke stage. |
| 2026-05-18 | — | AWS ALB/ELB (`f436`), Azure diagnostic JSON (`f437`), and generic JSON fallback (`f438`) parsers added. Azure covers Activity Log (`callerIpAddress`), App Gateway (`clientIP`), CDN (`clientIp`); Generic JSON covers Caddy (`remote_ip`), Traefik (`ClientHost`), and any custom JSON with common IP field names — key-prefix scan works at any nesting depth. 255 tests, triple sims 3/3, 14/14 standards. |
| 2026-05-18 | — | `/api/cf/pull` local proxy: browser calls same-machine whobelooking, server fires CF Analytics GraphQL, returns NDJSON; token in RAM for one round-trip, never stored. `/try` gets collapsible CF pull panel — zone ID + token + hours, feeds WASM pipeline. Install hint doubles as self-host funnel. |
| 2026-05-18 | — | GCP Cloud Logging JSON parser (`f439`) added. Binary pcap v2.4 + hex dump ingest (`f454–f457`): `f454` is the public binary entry point; `f455` decodes xxd/Wireshark/tcpdump/raw-hex text and routes through `f454` automatically from `f400`. Ethernet, raw IP, Linux SLL link types; IPv4 + IPv6 extraction; HTTP method/path/UA from TCP payload. `render` CLI now reads as bytes and auto-routes binary to `f454`. 265 tests, triple sims 3/3, 14/14 standards. |
| 2026-05-18 | 42c2f63 | Smoke test fix: CF edge returns HTTP 200 with empty NDJSON body for unknown tokens, not 401. `smoke_cf_pull_rejects_missing_zone` assertion changed from status-code check to `ndjson` content-type check. 269 unit + 8 smoke, all stages pass. |
| 2026-05-19 | — | `PidLock` drop-order fix — `_guard` field moved before `_file` in struct declaration. Rust drops fields in forward declaration order; `flock LOCK_UN` (guard) must fire before the fd closes (file). Prior field order left the fd invalid at unlock time. |
| 2026-05-19 | — | `cf-fleet` serde null crash fixed — `list_zones` `Resp` had `result: Vec<Zone>` which failed when CF API returned `result: null` (auth error, bad token, or empty account). Fixed with `#[serde(default)]`. All 10 zones now pull cleanly. |
| 2026-05-19 | — | `documentation` URL added to `Cargo.toml` `workspace.package` + `package` (`cochranblock.github.io/whobelooking/`). |
| 2026-05-19 | — | GitHub Pages docs fleshed out — 8 mdbook pages (introduction, getting-started, CLI reference, log-formats, /try, CF integration, configuration, architecture). Build workflow fixed and deploying. |
| 2026-05-19 | 7bfb58d | Default branch renamed `master` → `main`. |
| 2026-05-19 | — | Actor persistence — cross-report IP history stored in `actors.redb`. `whobelooking render` writes `ActorRecord {first_seen, last_seen, total_hits, total_reports, last_class}` per IP after each run and reads history before rendering. Cards show `↩ returning · first seen DATE · N reports · M total hits` badge on any IP seen in a prior report. `t105`/`t108` extended with optional history fields; `f402` carries them through. 269 tests, 14/14 standards, all stages pass. |
| 2026-05-19 | — | Multi-site combined report — `intel::render_html` adds: (1) **Zones column** in Top-25 IPs table showing which zones each IP hit and how many times; (2) **Cross-Site Actors section** — IPs appearing across ≥2 zones, sorted by zone count then CF hits, with org detail; (3) **Per-Zone Summary section** — per-zone top-5 IPs with hit counts and org. Surfaces cross-property recon patterns invisible in single-zone reports. 269 tests, 14/14 standards, all stages pass. |
| 2026-05-19 | — | Classification confidence scoring — `f404c` replaces `f404` as the canonical classifier, returning `(t104, u8)`. Confidence 0–100 derived from: attack-path variety (THREAT), crawler rDNS match (BOT), org-data + hit count + path diversity (INSTITUTIONAL), browser-UA + hit range (ORGANIC). `t105.confidence` field carries score through `f401`/`f402`; HTML cards show `NN%` badge alongside class tag. 269 tests, 14/14 standards. |
<!-- COCHRANBLOCK-BRAND-FOOTER:START - generated by cochranblock/scripts/brand-stamp.sh -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
