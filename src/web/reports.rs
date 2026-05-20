// Unlicense — public domain — whobelooking.org
//! `/reports` — history of locally generated HTML reports.

use axum::response::{Html, IntoResponse, Response};

pub async fn index() -> Response {
    let entries = crate::report_history::list(50);

    let esc = |s: &str| -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };

    let unix_to_date = |ts: u64| -> String {
        if ts == 0 {
            return String::from("—");
        }
        let z = (ts as i64).div_euclid(86400) + 719468;
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
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        let h = (ts / 3600) % 24;
        let mi = (ts / 60) % 60;
        format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m, d, h, mi)
    };

    let rows: String = if entries.is_empty() {
        r#"<tr><td colspan="5" style="text-align:center;color:#9ca3af;padding:24px;">
            No reports yet — run <code>whobelooking render &lt;logfile&gt;</code> to generate one.
        </td></tr>"#
            .into()
    } else {
        entries
            .iter()
            .map(|e| {
                let threat_color = if e.threat_count > 0 {
                    "#ff6b35"
                } else {
                    "#9ca3af"
                };
                format!(
                    r#"<tr>
  <td><a href="file://{path}" style="color:#00d9ff;">{label}</a></td>
  <td style="color:#9ca3af;">{when}</td>
  <td style="color:#e8e8e8;">{ips}</td>
  <td style="color:{tc};">{threats}</td>
  <td><a href="file://{path}" style="color:#666;font-size:10px;">open ↗</a></td>
</tr>"#,
                    path = esc(&e.path),
                    label = esc(&e.source_label),
                    when = unix_to_date(e.generated_at),
                    ips = e.total_ips,
                    threats = e.threat_count,
                    tc = threat_color,
                )
            })
            .collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Report History — whobelooking</title>
<style>
:root{{--bg:#050508;--surface:#0d0d14;--border:rgba(0,217,255,.15);--text:#e8e8e8;--muted:#9ca3af;--accent:#00d9ff;--mono:'JetBrains Mono',Consolas,monospace}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:12px;padding:32px}}
h1{{font-size:14px;color:var(--accent);letter-spacing:.2em;text-transform:uppercase;margin-bottom:24px}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border)}}
td{{padding:10px 12px;border-bottom:1px solid rgba(0,217,255,.05);font-size:11px;vertical-align:middle}}
code{{color:var(--accent);font-family:var(--mono)}}
a{{text-decoration:none}}
a:hover{{text-decoration:underline}}
</style></head><body>
<h1>whobelooking · report history</h1>
<table>
<thead><tr>
  <th>Source</th><th>Generated</th><th>IPs</th><th>Threats</th><th></th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<div style="margin-top:24px;font-size:10px;color:#555;">
  Reports register automatically when you run <code>whobelooking render</code>.
  Only reports whose files still exist on disk are shown.
</div>
</body></html>"#,
        rows = rows,
    );

    Html(html).into_response()
}
