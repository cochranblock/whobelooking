// Unlicense — public domain — whobelooking.org
//! HTML report renderer.
//!
//! Pure function — takes an `t107` plus a source label, returns
//! one self-contained HTML document. No external assets beyond Google Fonts
//! (one `<link>`); CSS and any small interactivity JS are inlined so the
//! report can be emailed, archived, or served from any static host.
//!
//! The visual target is `demo.html`: top bar / sidebar timeline / event feed
//! / right-panel stats. Aesthetics deliberately match so a customer who
//! liked the marketing demo gets the same layout on their own data.

use crate::aggregate::{t104, t105, t107};
use std::fmt::Write as _;

const CSS: &str = r#"
:root {
  --bg: #050508;
  --surface: #0d0d14;
  --surface2: #14141f;
  --border: rgba(0, 217, 255, 0.15);
  --text: #e8e8e8;
  --muted: #9ca3af;
  --accent: #00d9ff;
  --orange: #ff6b35;
  --teal: #00ffcc;
  --purple: #9d4edd;
  --glow: rgba(0, 217, 255, 0.35);
  --mono: 'JetBrains Mono','SF Mono',Consolas,monospace;
  --display: 'Orbitron',sans-serif;
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;line-height:1.5;overflow-x:hidden;min-height:100vh}
body::after{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");pointer-events:none;z-index:9999}
.shell{display:grid;grid-template-columns:260px 1fr 320px;grid-template-rows:40px 1fr;height:100vh}
.topbar{grid-column:1/-1;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 16px;gap:16px}
.topbar-logo{font-weight:800;color:var(--accent);font-size:14px;letter-spacing:.05em}
.topbar-sep{width:1px;height:20px;background:var(--border)}
.topbar-client{color:var(--muted);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar-status{margin-left:auto;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--teal)}
.topbar-status .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--teal);margin-right:6px}
.topbar-meta{color:var(--muted);font-size:10px;letter-spacing:.08em}
.sidebar{background:var(--surface);border-right:1px solid var(--border);padding:16px;overflow-y:auto}
.sidebar-title{font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px}
.day-entry{padding:8px 10px;margin-bottom:4px;border-radius:4px;font-size:11px;border-left:2px solid transparent}
.day-entry .day-label{color:var(--accent);font-weight:700;font-size:10px}
.day-entry .day-desc{color:var(--muted);font-size:10px;margin-top:2px}
.feed{padding:20px;overflow-y:auto}
.feed-header{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--orange);margin-bottom:16px}
.event{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:14px 16px;margin-bottom:10px}
.event.threat{border-left:3px solid var(--orange)}
.event.institutional{border-left:3px solid var(--accent)}
.event.organic{border-left:3px solid var(--teal)}
.event.bot{border-left:3px solid var(--muted);opacity:.7}
.event-time{font-size:9px;color:var(--muted);letter-spacing:.1em;margin-bottom:6px;text-transform:uppercase}
.event-title{font-size:12px;color:var(--text);font-weight:600;margin-bottom:4px;display:flex;flex-wrap:wrap;gap:6px;align-items:baseline}
.event-body{font-size:11px;color:var(--muted);line-height:1.5}
.event-body strong{color:var(--text)}
.event-body .org{color:var(--accent);font-weight:600}
.event-body .page{color:var(--purple)}
.event-body .ip{color:#666;font-size:10px}
.event-body .cc{color:var(--teal);font-size:10px;padding:0 4px;border:1px solid var(--border);border-radius:2px;margin-left:4px;text-transform:uppercase}
.tag{display:inline-block;font-size:8px;padding:2px 6px;border-radius:2px;font-weight:700;letter-spacing:.05em;margin-right:4px;text-transform:uppercase}
.tag-threat{background:var(--orange);color:var(--bg)}
.tag-bot{background:var(--muted);color:var(--bg)}
.tag-organic{background:var(--teal);color:var(--bg)}
.tag-institutional{background:var(--accent);color:var(--bg)}
.panel{background:var(--surface);border-left:1px solid var(--border);padding:16px;overflow-y:auto}
.panel-title{font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:16px}
.stat-block{margin-bottom:16px}
.stat-num{font-size:28px;font-weight:800;color:var(--accent);font-variant-numeric:tabular-nums}
.stat-label{font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.gauge{margin:14px 0}
.gauge-label{font-size:9px;color:var(--muted);margin-bottom:4px;letter-spacing:.1em;text-transform:uppercase;display:flex;justify-content:space-between}
.gauge-label span:last-child{color:var(--text)}
.gauge-track{width:100%;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.gauge-fill{height:100%;border-radius:2px}
.roster{margin-top:12px}
.roster-item{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:11px}
.roster-item:last-child{border-bottom:none}
.roster-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.roster-name{color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.roster-hits{color:var(--muted);margin-left:auto;font-size:10px;flex-shrink:0}
.empty{color:var(--muted);font-size:11px;padding:20px 0;text-align:center}
.legal{grid-column:1/-1;border-top:1px solid var(--border);padding:14px 20px;color:var(--muted);font-size:9px;letter-spacing:.2em;text-transform:uppercase;text-align:center;background:var(--surface)}
.legal a{color:var(--accent);text-decoration:none}
@media(orientation:portrait){.shell{grid-template-columns:1fr;grid-template-rows:40px auto;height:auto;min-height:100vh}.sidebar,.panel{display:none}.topbar-client{display:none}.topbar-sep{display:none}.feed{padding:12px}}
"#;

#[inline]
fn f440(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn f441(c: Option<t104>) -> u8 {
    match c {
        Some(t104::Threat) => 0,
        Some(t104::Institutional) => 1,
        Some(t104::Organic) => 2,
        Some(t104::Bot) => 3,
        None => 4,
    }
}

fn f442(c: Option<t104>) -> &'static str {
    c.map(|x| x.name()).unwrap_or("organic")
}

fn f443(c: Option<t104>) -> &'static str {
    match c {
        Some(t104::Threat) => "var(--orange)",
        Some(t104::Institutional) => "var(--accent)",
        Some(t104::Bot) => "var(--muted)",
        _ => "var(--teal)",
    }
}

fn f444(rec: &t105, fallback_ip: &str) -> String {
    if let Some(o) = &rec.org {
        if !o.is_empty() && rec.rdns.as_deref() != Some(o.as_str()) {
            return o.clone();
        }
    }
    if let Some(r) = &rec.rdns {
        if !r.is_empty() {
            let parts: Vec<&str> = r.split('.').filter(|p| !p.is_empty()).collect();
            if parts.len() >= 2 {
                let take = &parts[parts.len() - 2..];
                return take.join(".");
            }
            return r.clone();
        }
    }
    fallback_ip.to_string()
}

fn f445(unix: i64) -> String {
    if unix <= 0 {
        return String::new();
    }
    let (y, mo, d, h, mi, s) = f447(unix);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, mo, d, h, mi, s
    )
}

fn f446(unix: i64) -> String {
    if unix <= 0 {
        return String::new();
    }
    let (y, mo, d, _, _, _) = f447(unix);
    format!("{:04}-{:02}-{:02}", y, mo, d)
}

/// Civil-from-days reference algorithm (Howard Hinnant). No chrono dep.
fn f447(unix: i64) -> (i32, u32, u32, u32, u32, u32) {
    let z = unix.div_euclid(86400) + 719468;
    let secs = unix.rem_euclid(86400);
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = (if m <= 2 { y + 1 } else { y }) as i32;
    let h = (secs / 3600) as u32;
    let mi = ((secs % 3600) / 60) as u32;
    let s = (secs % 60) as u32;
    (y, m, d, h, mi, s)
}

fn f448(out: &mut String, source: &str, generated_at: i64, total_events: usize) {
    let _ = write!(
        out,
        r#"<div class="topbar">
  <span class="topbar-logo">whobelooking</span>
  <span class="topbar-sep"></span>
  <span class="topbar-client">SOURCE: {source}</span>
  <span class="topbar-status"><span class="dot"></span>REPORT READY</span>
  <span class="topbar-meta">{events} events · generated {when}</span>
</div>"#,
        source = f440(source),
        events = total_events,
        when = f445(generated_at),
    );
}

fn f449(out: &mut String, report: &t107) {
    out.push_str(r#"<div class="sidebar"><div class="sidebar-title">Timeline</div>"#);
    if report.days.is_empty() {
        out.push_str(r#"<div class="empty">no dated events</div>"#);
    } else {
        let mut days: Vec<(&i64, &crate::aggregate::t106)> = report.days.iter().collect();
        days.sort_by(|a, b| b.0.cmp(a.0));
        for (day, stat) in days {
            let unix = day * 86400;
            let label = f446(unix);
            let _ = write!(
                out,
                r#"<div class="day-entry">
  <div class="day-label">{label}</div>
  <div class="day-desc">{hits} visits · {ips} IPs</div>
</div>"#,
                label = f440(&label),
                hits = stat.hits,
                ips = stat.unique_ips,
            );
        }
    }
    out.push_str("</div>");
}

fn f450(out: &mut String, report: &t107, show_limit: usize) {
    // Feed header: total events + unique IPs, with a threat-count prefix
    // when applicable. The previous version showed `{N} IPs · {N} classified`
    // — both values were `report.ips.len()`, which made the secondary stat
    // meaningless. Reader gets three useful numbers now: how loud (events),
    // how many actors (IPs), and how many of those are dangerous (threats).
    let threats = report.class_counts.get("threat").copied().unwrap_or(0);
    out.push_str(r#"<div class="feed"><div class="feed-header">"#);
    if threats > 0 {
        let _ = write!(
            out,
            r#"<span style="color:var(--orange)">{} THREAT</span> · {} events · {} IPs"#,
            threats,
            report.total_events,
            report.ips.len(),
        );
    } else {
        let _ = write!(
            out,
            "EVENT FEED · {} events · {} IPs",
            report.total_events,
            report.ips.len(),
        );
    }
    out.push_str("</div>");

    let mut entries: Vec<(&String, &t105)> = report.ips.iter().collect();
    entries.sort_by(|a, b| {
        f441(a.1.class)
            .cmp(&f441(b.1.class))
            .then(b.1.hits.cmp(&a.1.hits))
    });

    let mut rendered = 0usize;
    for (ip, rec) in entries.iter().take(show_limit) {
        let top_path = rec
            .paths
            .iter()
            .max_by_key(|(_, n)| *n)
            .map(|(p, n)| (p.as_str(), *n))
            .unwrap_or(("—", 0));
        let top_ua = rec
            .user_agents
            .iter()
            .max_by_key(|(_, n)| *n)
            .map(|(u, _)| u.as_str())
            .unwrap_or("—");
        let cc = rec
            .countries
            .keys()
            .next()
            .cloned()
            .or_else(|| rec.org_country.clone())
            .unwrap_or_default();
        let class = f442(rec.class);
        let org_name = f444(rec, ip);
        let show_org = org_name.as_str() != ip.as_str();

        let _ = write!(
            out,
            r#"<div class="event {class}">
  <div class="event-time">{when} · {hits} hit{plural}</div>
  <div class="event-title">
    <span class="tag tag-{class}">{class_up}</span>
    {primary}
    {cc_block}
  </div>
  <div class="event-body">
    {ip_block}
    Top path: <span class="page">{path}</span>{count_block}
    <br><span style="color:#444;font-size:10px;">{ua}</span>
  </div>
</div>"#,
            class = class,
            class_up = class.to_ascii_uppercase(),
            when = f445(rec.last_unix),
            hits = rec.hits,
            plural = if rec.hits > 1 { "s" } else { "" },
            primary = if show_org {
                format!(r#"<span class="org">{}</span>"#, f440(&org_name))
            } else {
                format!(r#"<span class="ip">{}</span>"#, f440(ip))
            },
            cc_block = if cc.is_empty() {
                String::new()
            } else {
                format!(r#"<span class="cc">{}</span>"#, f440(&cc))
            },
            ip_block = if show_org {
                let rdns = rec
                    .rdns
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|s| format!(" · {}", f440(s)))
                    .unwrap_or_default();
                format!(r#"<span class="ip">{}{}</span><br>"#, f440(ip), rdns)
            } else {
                String::new()
            },
            path = f440(top_path.0),
            count_block = if top_path.1 > 1 {
                format!(" ({}×)", top_path.1)
            } else {
                String::new()
            },
            ua = f440(&f451(top_ua, 140)),
        );
        rendered += 1;
    }

    if rendered == 0 {
        out.push_str(r#"<div class="empty">no events — is this a recognized log format?</div>"#);
    } else if entries.len() > show_limit {
        let _ = write!(
            out,
            r#"<div class="empty">+ {} more IPs (showing top {})</div>"#,
            entries.len() - show_limit,
            show_limit,
        );
    }
    out.push_str("</div>");
}

fn f451(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out = String::with_capacity(max);
        for (i, c) in s.chars().enumerate() {
            if i >= max {
                break;
            }
            out.push(c);
        }
        out.push('…');
        out
    }
}

fn f452(out: &mut String, report: &t107) {
    out.push_str(r#"<div class="panel"><div class="panel-title">Report</div>"#);

    let _ = write!(
        out,
        r#"<div class="stat-block"><div class="stat-num">{}</div><div class="stat-label">total visits</div></div>"#,
        report.total_events,
    );
    let _ = write!(
        out,
        r#"<div class="stat-block"><div class="stat-num">{}</div><div class="stat-label">unique IPs</div></div>"#,
        report.ips.len(),
    );
    let _ = write!(
        out,
        r#"<div class="stat-block"><div class="stat-num">{}</div><div class="stat-label">distinct paths</div></div>"#,
        report.distinct_paths,
    );

    out.push_str(r#"<div class="panel-title" style="margin-top:24px">Classification</div>"#);
    let total = report.ips.len().max(1) as f64;
    let buckets = [
        ("institutional", "var(--accent)"),
        ("organic", "var(--teal)"),
        ("threat", "var(--orange)"),
        ("bot", "var(--muted)"),
    ];
    for (key, color) in &buckets {
        let count = report.class_counts.get(*key).copied().unwrap_or(0);
        let pct = (100.0 * count as f64 / total).round() as u32;
        let _ = write!(
            out,
            r#"<div class="gauge">
  <div class="gauge-label"><span>{key}</span><span>{pct}%</span></div>
  <div class="gauge-track"><div class="gauge-fill" style="background:{color};width:{pct}%"></div></div>
</div>"#,
            key = key,
            pct = pct,
            color = color,
        );
    }

    out.push_str(r#"<div class="panel-title" style="margin-top:24px">Top entities</div><div class="roster">"#);
    // Roster aggregates per displayed-label (org name fallback to IP). When
    // multiple IPs collapse under the same label, the dot must show the
    // *worst* class across all of them — a threat IP sharing a /24 with a
    // bot must surface as Threat, not Bot. `f441` ranks Threat (0)
    // before Institutional (1) < Organic (2) < Bot (3); we keep the lowest
    // rank seen.
    let mut by_org: std::collections::BTreeMap<String, (u32, Option<t104>)> =
        std::collections::BTreeMap::new();
    for (ip, rec) in &report.ips {
        let key = f444(rec, ip);
        let e = by_org.entry(key).or_insert((0, rec.class));
        e.0 += rec.hits;
        if f441(rec.class) < f441(e.1) {
            e.1 = rec.class;
        }
    }
    let mut sorted: Vec<(String, (u32, Option<t104>))> = by_org.into_iter().collect();
    sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    let mut roster_rendered = 0usize;
    for (label, (hits, class)) in sorted.iter().take(30) {
        let _ = write!(
            out,
            r#"<div class="roster-item">
  <span class="roster-dot" style="background:{color}"></span>
  <span class="roster-name">{name}</span>
  <span class="roster-hits">{hits}</span>
</div>"#,
            color = f443(*class),
            name = f440(label),
            hits = hits,
        );
        roster_rendered += 1;
    }
    if roster_rendered == 0 {
        out.push_str(r#"<div class="empty">no IPs</div>"#);
    }
    out.push_str("</div></div>");
}

/// Render a complete self-contained HTML document for the given report.
/// `source_label` shows up in the top bar (eg the log file name); set to
/// `"surface scan"` or similar for non-log report contexts.
/// f405 = render_html
pub fn f405(report: &t107, source_label: &str) -> String {
    let generated_at = f453();
    let mut html = String::with_capacity(64 * 1024);
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    html.push_str(r#"<meta name="viewport" content="width=device-width,initial-scale=1">"#);
    let _ = write!(
        html,
        "<title>{} — whobelooking report</title>",
        f440(source_label),
    );
    html.push_str(r#"<meta name="generator" content="whobelooking (wbl-detect)">"#);
    html.push_str(r#"<link rel="preconnect" href="https://fonts.googleapis.com">"#);
    html.push_str(r#"<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>"#);
    html.push_str(r#"<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700&family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">"#);
    html.push_str("<style>");
    html.push_str(CSS);
    html.push_str("</style></head><body><div class=\"shell\">");

    f448(&mut html, source_label, generated_at, report.total_events);
    f449(&mut html, report);
    f450(&mut html, report, 200);
    f452(&mut html, report);

    html.push_str(r#"<div class="legal">whobelooking · Unlicense · runs locally · <a href="https://github.com/cochranblock/whobelooking">github.com/cochranblock/whobelooking</a></div>"#);
    html.push_str("</div></body></html>");
    html
}

fn f453() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        // In WASM we rely on the host JS Date.now() bridged via wasm-bindgen
        // through js_sys when available, but a simple approach is to call
        // performance.now-equivalent. Falling back to 0 keeps the renderer
        // deterministic for tests / replay.
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::f401;
    use crate::parse::t100;

    fn ev(ip: &str, path: &str, ua: &str) -> t100 {
        t100 {
            ts: 1_700_000_000,
            ip: ip.into(),
            cc: "US".into(),
            method: "GET".into(),
            path: path.into(),
            ua: ua.into(),
            referrer: "".into(),
        }
    }

    #[test]
    fn renders_basic_report() {
        let events = vec![
            ev("1.1.1.1", "/.env", "Mozilla/5.0"),
            ev("2.2.2.2", "/", "Googlebot"),
            ev("3.3.3.3", "/about", "Mozilla/5.0 Chrome"),
        ];
        let report = f401(&events);
        let html = f405(&report, "sample.log");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("THREAT"));
        assert!(html.contains("/.env"));
        assert!(html.contains("BOT"));
        assert!(html.contains("INSTITUTIONAL"));
        assert!(html.contains("sample.log"));
    }

    #[test]
    fn html_escapes_paths_and_uas() {
        let events = vec![ev("1.1.1.1", "/x?<script>", "Mozilla & Co")];
        let report = f401(&events);
        let html = f405(&report, "test.log");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Mozilla &amp; Co"));
    }
}
