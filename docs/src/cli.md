# CLI Reference

## Analysis

### `render`

Parse a log file and produce a standalone HTML intelligence report. Same pipeline as `/try`.

```
whobelooking render <FILE> [-o <OUT>]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `FILE` | required | Path to any supported log file (auto-detected format) |
| `-o, --out` | `<FILE>.html` | Output path |

---

### `intel`

Full pipeline: base logs + Cloudflare enrichment + rDNS + RDAP → two HTML reports (redacted and unredacted).

```
whobelooking intel --token <TOKEN> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --token` | `$CF_TOKEN` | Cloudflare API token |
| `--baselogs-dir` | `/tmp/wbl-baselogs` | Directory of base log files |
| `--hours` | `48` | Lookback window in hours |
| `-o, --out` | `/tmp/wbl-intel` | Output directory |

Writes `intel.unredacted.html` and `intel.redacted.html`.

---

### `detect`

Detect column types in a log or CSV file using the same auto-detection engine as `/detect`.

```
whobelooking detect <FILE> [--json] [--max-rows <N>]
```

---

### `parse-logs`

Parse `visit ip=…` base log files, aggregate per-IP, classify, and emit JSON to stdout.

```
whobelooking parse-logs [FILES...] [--hours <N>]
```

---

## Cloudflare

### `cf-fleet`

Pull `httpRequestsAdaptiveGroups` for every zone the token can see, across 24h windows.

```
whobelooking cf-fleet --token <TOKEN> [--hours 48] [--out /tmp/wbl-cf-fleet.json]
```

### `cf-enrich`

Enrich a list of IPs against all CF zones (both `httpRequestsAdaptiveGroups` and `firewallEventsAdaptive`). Reads IPs from stdin or a file.

```
whobelooking cf-enrich --token <TOKEN> [--hours 48] [IPs...]
```

### `pull`

Pull US visitor IPs from Cloudflare GraphQL for a given date (legacy, single-zone).

```
whobelooking pull --zone <ZONE_ID> --token <TOKEN> [--date YYYY-MM-DD] [--country US]
```

---

## Enrichment

### `rdns`

Reverse DNS lookup on a list of IPs (or stdin).

```
whobelooking rdns [IPs...]
```

### `rdap`

RDAP WHOIS lookup on a list of IPs — org / netname / country. Results cached on disk.

```
whobelooking rdap [IPs...]
```

### `neighbors`

Scan all 256 PTR records in an IP's /24 subnet — reveals co-tenants and company names.

```
whobelooking neighbors <IP>
```

### `report`

Full pipeline: `pull` → `rdns` → neighbor scan → report.

```
whobelooking report --zone <ZONE_ID> --token <TOKEN>
```

---

## Scout (Federal Intelligence)

```
whobelooking scout [OPTIONS]
```

Searches SAM.gov, USASpending, SBIR, Federal Register, Grants.gov, Contract Awards, Regulations.gov, and GSA CALC+ for contract opportunities.

---

## Operations

| Command | Description |
|---------|-------------|
| `whobelooking serve [--port 8082]` | Start the web server |
| `whobelooking queue` | List all jobs in the queue |
| `whobelooking pop` | Take the next pending job |
| `whobelooking done <id>` | Mark a job complete |
| `whobelooking deliver <id>` | Mark a job delivered |
| `whobelooking order` | Manage the order queue (list / approve / reject / ready / audit) |
| `whobelooking visits [N]` | Show today's visits (or N days ago) |
| `whobelooking ping` | Check whether the IPC socket is alive |
| `whobelooking corpus` | Export the captured-paths corpus from the visits tree |
| `whobelooking decrypt` | Decrypt a credential blob (from email) using your local key |
| `whobelooking scan <URL>` | Probe 140+ attack-surface paths against a URL |
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
