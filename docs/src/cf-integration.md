# Cloudflare Integration

whobelooking has first-class Cloudflare support: pull traffic data from CF Analytics GraphQL, enrich IPs across zones, and feed it all into the same pipeline as any other log format.

## Token Requirements

Your Cloudflare API token needs:

- **Zone: Analytics: Read** — for `httpRequestsAdaptiveGroups` and `firewallEventsAdaptive`
- **Account: Analytics: Read** — for `cf-fleet` across all zones

Set it in your environment:

```bash
export CF_TOKEN=your_token_here
```

Or pass it with `--token` on any command.

## Pull a Single Zone

```bash
# Pull US visitors for today
whobelooking pull --zone <zone_id> --token $CF_TOKEN

# Different date or country
whobelooking pull --zone <zone_id> --date 2026-05-18 --country GB
```

## Pull All Zones (Fleet)

```bash
# Pull 48h of data across every zone the token can see
whobelooking cf-fleet --hours 48 --out /tmp/fleet.json
```

Output is a JSON map of zone name → array of `{count, ip, country, host, path, status, user_agent}` records.

## Enrich IPs

Given a list of IPs, cross-reference them against all CF zones to get hit counts, paths, firewall events, and countries:

```bash
cat ips.txt | whobelooking cf-enrich --token $CF_TOKEN --hours 48
```

## /api/cf/pull (Browser Endpoint)

When the server is running, the browser's `/try` CF panel calls:

```
GET /api/cf/pull?zone_id=<32-hex>&token=<token>&hours=<N>
```

The server fires the CF GraphQL query and streams back NDJSON. The token stays in RAM for the duration of the request and is never logged or stored.

**Validation:**
- `zone_id` must be exactly 32 lowercase hex characters
- `token` must be non-empty
- Returns `400` for malformed inputs before any network call is made

## Full Intel Pipeline

```bash
# Base logs + CF pull + rDNS + RDAP → HTML
whobelooking intel \
  --token $CF_TOKEN \
  --baselogs-dir /path/to/logs \
  --hours 48 \
  --out /tmp/intel
```

Writes `intel.unredacted.html` (full IPs) and `intel.redacted.html` (IPs masked for sharing).
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
