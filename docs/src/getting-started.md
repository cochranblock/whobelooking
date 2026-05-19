# Getting Started

## Requirements

- Rust 1.85+
- A log file or Cloudflare API token

## Build

```bash
# CLI only (no web server)
cargo build

# With web server
cargo build --features serve

# Production binary (diamond profile — stripped, LTO, opt=3)
cargo build --profile diamond --features serve
```

## Analyze a Log File

```bash
# Any supported format — auto-detected
whobelooking render access.log

# Output path defaults to access.log.html
# Override:
whobelooking render access.log -o report.html
```

Opens the HTML in a browser — standalone, no external dependencies.

## Pull from Cloudflare and Render

```bash
export CF_TOKEN=your_cloudflare_token

# Pull 48h across all zones you have access to
whobelooking cf-fleet --hours 48 --out /tmp/fleet.json

# Pull a single zone
whobelooking pull --zone <zone_id> --date 2026-05-19

# Full pipeline: CF pull + rDNS + RDAP → HTML
whobelooking intel --token $CF_TOKEN --hours 48 --out /tmp/intel
```

## Run the Web Server

```bash
whobelooking serve --port 8082
```

Then open `http://localhost:8082/try` — drop a log file in the browser, get an HTML report back. No upload. WASM runs the pipeline locally.

## Run the Test Suite

```bash
# Full gate: compile + 269 unit tests + triple sims + 14 standards + 8 smoke tests
# Requires a running server on :8082
cargo run --features tests --bin whobelooking-test
```
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
