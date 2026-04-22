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
