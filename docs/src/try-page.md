# /try — In-Browser Analysis

`/try` runs the full analysis pipeline in the browser via WebAssembly. Your log files never leave your machine.

## What Happens

1. Drop a log file (any supported format) onto the page
2. `wbl-detect` WASM (~219 KB) parses, aggregates, and classifies the data in-browser
3. For each unique IP, the browser queries DoH (DNS-over-HTTPS) for PTR records and RDAP for org info
4. A standalone HTML report is rendered and available for download

No server-side processing. No upload. The browser is the analysis engine.

## The CF Pull Panel

The collapsible **Pull from Cloudflare** panel lets you pull traffic data directly from Cloudflare Analytics into the pipeline:

| Field | Description |
|-------|-------------|
| Zone ID | 32-char hex Cloudflare zone identifier |
| API Token | Cloudflare API token with Analytics Read permission |
| Hours | Lookback window (default 24) |

The browser calls `/api/cf/pull` on the local whobelooking server, which fires the CF GraphQL query and returns NDJSON. The token is in RAM for one round-trip and never stored. The NDJSON feeds the same WASM pipeline as a dropped file.

## Report Output

The rendered report includes:

- **Topbar** — total visits, unique IPs, distinct paths
- **Timeline sidebar** — day-by-day visit counts
- **IP feed** — one card per unique IP, classified and enriched:
  - Classification badge (THREAT / INSTITUTIONAL / ORGANIC / BOT)
  - rDNS hostname + org name
  - Country, hit count, top paths, user-agent
- **Stats panel** — classification breakdown (%), top entities ranked by hits

## Download

The report is a standalone HTML file — no external dependencies, no JavaScript required to view it. Send it, archive it, open it offline.

## Airgap Mode

On isolated networks, `/try` can be configured to use internal DNS, RDAP, and font servers. See [Configuration](configuration.md#airgap).
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
