# whobelooking

Visitor intelligence platform. Any IP source → rDNS → /24 scan → WHOIS → company ID → enrichment flywheel → intelligence report.

One binary. Zero cloud. [Unlicense](https://github.com/cochranblock/whobelooking/blob/master/LICENSE).

## What It Does

Drop any log file — Cloudflare NDJSON, nginx access log, AWS ALB, pcap, anything — and get back a standalone HTML report that tells you which companies visited, which pages they read, how long they stayed, and whether they look like a threat or an opportunity.

Real example: cochranblock.org caught Microsoft evaluating the site across 14 IPs and 4 network ranges over 8 consecutive days. They downloaded the resume 5 times. Initial discovery traced to a LinkedIn post — same hour, same page, zero lag. Total marketing spend: $0.

## How It Works

```
Any log source → parse → aggregate per-IP → rDNS → RDAP → classify → HTML report
```

Parsing, classification, and rendering all run in a single WASM module (`wbl-detect`, ~219 KB). The same binary runs in the browser on `/try` and on the server via `whobelooking render`.

## Key Numbers

| Metric | Value |
|--------|-------|
| Binary size | 7.3 MB (dev) |
| WASM size | ~219 KB |
| Log formats supported | 17 |
| Unit tests | 269 |
| Smoke tests | 8 |
| Standards gate | 14/14 |

## License

Unlicense — public domain. Do what you want.
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
