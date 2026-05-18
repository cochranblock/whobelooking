// All Rights Reserved — The Cochran Block, LLC
//! Pages for whobelooking.org — story first, sample report prominent, sell the feeling.

use crate::queue;
use axum::response::Html;

const DEMO_HTML: &str = include_str!("../../demo.html");

pub async fn demo() -> Html<&'static str> {
    Html(DEMO_HTML)
}

pub async fn index() -> Html<String> {
    let hours = queue::hours_this_week();
    let (ips, companies) = queue::enrichment_stats();
    let capacity_pct = ((hours / 12.0) * 100.0).min(100.0) as u32;

    Html(format!(
        r##"<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>whobelooking — Who's looking at your site?</title>
<meta name="description" content="Visitor intelligence. We tell you which companies are silently evaluating your site, which pages they read, and what it means. Free. Unlicense.">
<meta property="og:title" content="whobelooking — Visitor Intelligence">
<meta property="og:description" content="Microsoft had a 3-hour meeting about us. We caught them. Want to know who's meeting about you?">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&family=Orbitron:wght@400;500;600;700&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
  --bg: #050508;
  --surface: #0d0d14;
  --surface2: #14141f;
  --text: #e8e8e8;
  --muted: #9ca3af;
  --amber: #00d9ff;
  --red: #ff6b35;
  --green: #00ffcc;
  --blue: #9d4edd;
  --purple: rgba(0, 217, 255, 0.35);
  --mono: 'JetBrains Mono', 'SF Mono', Consolas, monospace;
  --serif: 'Orbitron', sans-serif;
}}
*, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}
html {{ scroll-behavior: smooth; }}
body {{ background: var(--bg); color: var(--text); font-family: var(--mono); font-size: 15px; line-height: 1.6; overflow-x: hidden; }}

/* Grain overlay */
body::before {{
  content: '';
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 9999;
}}

.page {{ max-width: 720px; margin: 0 auto; padding: 3rem 1.5rem; }}

/* Classification banner */
.classification {{
  font-size: 0.55rem;
  letter-spacing: 0.35em;
  text-transform: uppercase;
  color: var(--red);
  text-align: center;
  padding: 8px 0;
  border: 1px solid rgba(255, 97, 136, 0.3);
  margin-bottom: 4rem;
  opacity: 0;
  animation: fadeIn 0.6s 0.2s forwards;
}}

/* Hero */
.hero {{ margin-bottom: 4rem; }}
.hero-kicker {{
  font-size: 0.65rem;
  letter-spacing: 0.3em;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 1rem;
  opacity: 0;
  animation: fadeIn 0.6s 0.4s forwards;
}}
.hero h1 {{
  font-family: var(--serif);
  font-size: clamp(2.5rem, 7vw, 4rem);
  font-weight: 400;
  
  color: var(--amber);
  line-height: 1.1;
  margin-bottom: 1.5rem;
  opacity: 0;
  animation: fadeIn 0.8s 0.6s forwards;
}}
.hero-sub {{
  font-size: 1rem;
  color: var(--text);
  max-width: 540px;
  opacity: 0;
  animation: fadeIn 0.6s 0.9s forwards;
}}

/* The proof — the hook */
.proof {{
  background: var(--surface);
  border: 1px solid rgba(255, 216, 102, 0.15);
  padding: 2rem;
  margin: 3rem 0;
  position: relative;
  opacity: 0;
  animation: fadeIn 0.6s 1.1s forwards;
}}
.proof::before {{
  content: 'VERIFIED SIGNAL';
  position: absolute;
  top: -10px;
  left: 20px;
  background: var(--bg);
  padding: 0 10px;
  font-size: 0.55rem;
  letter-spacing: 0.25em;
  color: var(--amber);
}}
.proof-headline {{
  font-family: var(--serif);
  font-size: 1.5rem;
  
  color: var(--text);
  margin-bottom: 1rem;
  line-height: 1.3;
}}
.proof-stat {{
  display: flex;
  gap: 2rem;
  margin: 1.5rem 0;
  flex-wrap: wrap;
}}
.proof-stat-item {{
  text-align: center;
}}
.proof-stat-num {{
  font-size: 1.8rem;
  font-weight: 800;
  color: var(--amber);
  display: block;
}}
.proof-stat-label {{
  font-size: 0.55rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--muted);
}}
.proof-link {{
  display: inline-block;
  margin-top: 1rem;
  color: var(--amber);
  text-decoration: none;
  font-size: 0.85rem;
  border-bottom: 1px solid rgba(255, 216, 102, 0.3);
  padding-bottom: 2px;
  transition: border-color 0.2s;
}}
.proof-link:hover {{ border-color: var(--amber); }}

/* Terminal */
.terminal {{
  background: #0d0d0d;
  border: 1px solid #333;
  border-radius: 6px;
  margin: 3rem 0;
  overflow: hidden;
  opacity: 0;
  animation: fadeIn 0.6s 1.4s forwards;
}}
.terminal-bar {{
  background: #050508;
  padding: 8px 14px;
  display: flex;
  align-items: center;
  gap: 6px;
  border-bottom: 1px solid #333;
}}
.terminal-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
.terminal-dot:nth-child(1) {{ background: #ff5f57; }}
.terminal-dot:nth-child(2) {{ background: #febc2e; }}
.terminal-dot:nth-child(3) {{ background: #28c840; }}
.terminal-title {{ font-size: 0.65rem; color: var(--muted); margin-left: 8px; }}
.terminal-body {{
  padding: 1.2rem;
  font-size: 0.75rem;
  line-height: 1.8;
  min-height: 180px;
  color: var(--green);
}}
.terminal-body .ip {{ color: var(--muted); }}
.terminal-body .arrow {{ color: #555; }}
.terminal-body .org {{ color: var(--amber); }}
.terminal-body .hits {{ color: var(--blue); }}
.terminal-body .path {{ color: var(--text); }}
.terminal-body .blocked {{ color: var(--red); font-weight: 700; }}
.terminal-body .cursor {{ display: inline-block; width: 8px; height: 14px; background: var(--green); animation: blink 1s step-end infinite; vertical-align: middle; }}

/* Sections */
.section {{ margin: 4rem 0; }}
.section-label {{
  font-size: 0.55rem;
  letter-spacing: 0.3em;
  text-transform: uppercase;
  color: var(--red);
  margin-bottom: 1rem;
}}
.section h2 {{
  font-family: var(--serif);
  font-size: 1.8rem;
  font-weight: 400;
  
  color: var(--text);
  margin-bottom: 1.5rem;
  line-height: 1.2;
}}
.section p {{ color: var(--muted); margin-bottom: 1rem; font-size: 0.9rem; }}
.section strong {{ color: var(--text); }}

/* Steps */
.steps {{ display: flex; flex-direction: column; gap: 1.5rem; margin: 2rem 0; }}
.step {{ display: flex; gap: 1.2rem; align-items: flex-start; }}
.step-num {{
  width: 32px; height: 32px;
  background: var(--amber);
  color: var(--bg);
  font-weight: 800;
  font-size: 0.8rem;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  flex-shrink: 0;
}}
.step-content h3 {{ color: var(--text); font-size: 0.95rem; margin-bottom: 0.3rem; }}
.step-content p {{ color: var(--muted); font-size: 0.85rem; margin: 0; }}

/* Pricing */
.pricing {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 2rem 0; }}
.price-card {{
  background: var(--surface);
  border: 1px solid #333;
  padding: 1.5rem;
  text-align: center;
  transition: border-color 0.2s, transform 0.2s;
}}
.price-card:hover {{ border-color: var(--amber); transform: translateY(-2px); }}
.price-card.featured {{ border-color: var(--amber); }}
.price-tier {{ font-size: 0.6rem; letter-spacing: 0.2em; text-transform: uppercase; color: var(--muted); margin-bottom: 0.5rem; }}
.price-amount {{ font-size: 1.8rem; font-weight: 800; color: var(--amber); }}
.price-ips {{ font-size: 0.7rem; color: var(--muted); margin-top: 0.3rem; }}
.price-hours {{ font-size: 0.65rem; color: #555; margin-top: 0.2rem; }}

/* Capacity */
.capacity {{ margin: 3rem 0; }}
.capacity-track {{
  width: 100%;
  height: 6px;
  background: rgba(0, 217, 255, 0.15);
  border-radius: 3px;
  overflow: hidden;
  margin: 0.8rem 0;
}}
.capacity-fill {{
  height: 100%;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--green), var(--amber));
  transition: width 1s ease;
}}
.capacity-label {{ font-size: 0.65rem; color: var(--muted); }}
.capacity-note {{ font-size: 0.75rem; color: #555; margin-top: 0.5rem; }}

/* Enrichment counter */
.enrichment {{
  display: flex;
  gap: 3rem;
  margin: 2rem 0;
  padding: 1.5rem 0;
  border-top: 1px solid rgba(0, 217, 255, 0.15);
  border-bottom: 1px solid rgba(0, 217, 255, 0.15);
}}
.enrichment-item {{ }}
.enrichment-num {{
  font-size: 1.5rem;
  font-weight: 800;
  color: var(--green);
  font-variant-numeric: tabular-nums;
}}
.enrichment-label {{
  font-size: 0.55rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--muted);
}}

/* CTA */
.cta {{
  margin: 4rem 0;
  padding: 2.5rem;
  background: var(--surface);
  border: 1px solid rgba(255, 216, 102, 0.15);
  text-align: center;
}}
.cta h2 {{
  font-family: var(--serif);
  font-size: 1.5rem;
  
  color: var(--text);
  margin-bottom: 1rem;
}}
.cta p {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }}
.btn {{
  display: inline-block;
  padding: 12px 32px;
  background: var(--amber);
  color: var(--bg);
  font-family: var(--mono);
  font-weight: 700;
  font-size: 0.85rem;
  text-decoration: none;
  letter-spacing: 0.05em;
  transition: background 0.2s, transform 0.1s;
}}
.btn:hover {{ background: #ffe588; transform: translateY(-1px); }}
.btn-ghost {{
  background: transparent;
  border: 1px solid var(--amber);
  color: var(--amber);
  margin-left: 0.5rem;
}}
.btn-ghost:hover {{ background: rgba(255, 216, 102, 0.08); }}

/* Who */
.who {{ font-size: 0.85rem; color: var(--muted); margin: 2rem 0; }}
.who strong {{ color: var(--text); }}

/* Footer */
.footer {{
  margin-top: 4rem;
  padding-top: 1.5rem;
  border-top: 1px solid rgba(0, 217, 255, 0.15);
  font-size: 0.55rem;
  color: #555;
  text-align: center;
  letter-spacing: 0.05em;
}}

/* Animations */
@keyframes fadeIn {{
  from {{ opacity: 0; transform: translateY(8px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes blink {{
  50% {{ opacity: 0; }}
}}

/* Mobile */
@media (orientation: portrait) {{
  .page {{ padding: 2rem 1rem; }}
  .proof-stat {{ gap: 1rem; }}
  .pricing {{ grid-template-columns: 1fr 1fr; }}
  .enrichment {{ gap: 1.5rem; }}
  .btn-ghost {{ margin-left: 0; margin-top: 0.5rem; }}
}}
</style></head><body>
<div class="page">

<div class="classification">whobelooking.org &middot; visitor intelligence &middot; all rights reserved</div>

<div class="hero">
  <div class="hero-kicker">The Cochran Block, LLC</div>
  <h1>Who's looking at your site?</h1>
  <p class="hero-sub">We tell you which companies are silently evaluating you. Which pages they read. How long they stayed. Whether they're a threat or an opportunity. Free, Unlicense.</p>
</div>

<div class="proof">
  <p class="proof-headline">Microsoft evaluated us across 14 IP addresses over 8 consecutive days. They downloaded our resume 5 times. We caught every visit.</p>
  <div class="proof-stat">
    <div class="proof-stat-item"><span class="proof-stat-num">14</span><span class="proof-stat-label">Microsoft IPs</span></div>
    <div class="proof-stat-item"><span class="proof-stat-num">8</span><span class="proof-stat-label">Consecutive Days</span></div>
    <div class="proof-stat-item"><span class="proof-stat-num">$0</span><span class="proof-stat-label">Marketing Spend</span></div>
    <div class="proof-stat-item"><span class="proof-stat-num">3</span><span class="proof-stat-label">Eval Tracks Found</span></div>
  </div>
  <a href="/sample" class="proof-link">Read the full intelligence report &rarr;</a>
</div>

<div class="terminal">
  <div class="terminal-bar">
    <div class="terminal-dot"></div><div class="terminal-dot"></div><div class="terminal-dot"></div>
    <span class="terminal-title">whobelooking report &mdash; live</span>
  </div>
  <div class="terminal-body" id="term"></div>
</div>

<div class="section">
  <div class="section-label">How It Works</div>
  <h2>Send data. Get intelligence.</h2>
  <div class="steps">
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-content">
        <h3>Send us your traffic data</h3>
        <p>Cloudflare credentials, an access log, a CSV. Any source of IP addresses. We never touch your server.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-content">
        <h3>We run the pipeline</h3>
        <p>Reverse DNS, /24 neighbor scanning, RDAP whois, company identification, LinkedIn correlation, threat detection. Every result cached in the enrichment database.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-content">
        <h3>You get the intelligence</h3>
        <p>A PDF report reviewed by a USCYBERCOM operator. Not an algorithm. A human who's done this for 13 years. Confidence gauges, institutional identification, threat assessment, and recommendations.</p>
      </div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-label">Free</div>
  <h2>Free, every report, no tiers</h2>
  <p>Unlicense / public domain. No paywall, no usage caps, no per-IP fees. Source on GitHub. Run it yourself or send it through here.</p>
  <p style="font-size:0.75rem;color:#555">Every report is manually reviewed. Automation earns its place by passing the creator's quality gate &mdash; same philosophy as <a href="https://knox.cochranblock.org" style="color:var(--muted)">KNOXAI</a>.</p>
</div>

<div class="section">
  <div class="section-label">The Flywheel</div>
  <h2>Every report makes the next one smarter</h2>
  <p>When we resolve an IP to a company, that mapping is cached forever. Customer #1's Microsoft identification helps Customer #50's report resolve instantly. The more sites in the system, the better every report gets.</p>
  <div class="enrichment">
    <div class="enrichment-item">
      <div class="enrichment-num" id="ip-count">{ips}</div>
      <div class="enrichment-label">IPs resolved</div>
    </div>
    <div class="enrichment-item">
      <div class="enrichment-num" id="co-count">{companies}</div>
      <div class="enrichment-label">Companies identified</div>
    </div>
  </div>
  <p style="font-size:0.75rem;color:#555">Early adopter advantage: you're building the database. The price reflects that.</p>
</div>

<div class="capacity">
  <div class="section-label">Capacity</div>
  <div class="capacity-track"><div class="capacity-fill" style="width:{capacity_pct}%"></div></div>
  <div class="capacity-label">{hours:.1} of 12 hours committed this week</div>
  <div class="capacity-note">One person. Every report gets full attention.</div>
</div>

<div class="cta">
  <h2>Find out who's watching.</h2>
  <p>Email your site URL, source type, and credentials. You'll get a confirmation within 24 hours.</p>
  <a href="https://github.com/cochranblock/whobelooking" class="btn">Get the source — free</a>
  <a href="/sample" class="btn btn-ghost">View Sample</a>
</div>

<div class="who">
  <strong>Michael Cochran</strong> &mdash; Army 17C, USCYBERCOM J38, 13 years defense &amp; enterprise. The person who caught Microsoft, Google, IBM, and the SEC visiting his site with zero marketing spend. The tool that caught them runs your report.
</div>

<div class="footer">
  Unlicense &mdash; public domain &mdash; The Cochran Block, LLC &mdash; CAGE 1CQ66 &mdash; UEI W7X3HAQL9CF9<br>
  whobelooking v0.2.0 &middot; <a href="/try" style="color:inherit">/try in your browser</a>
</div>

</div>

<script>
(function() {{
  var lines = [
    ['74.179.x.x', 'Microsoft Corporation', '53 hits', '/deck, /arch, /apply'],
    ['216.252.x.x', 'Google VPN (Corp)', '4 hits', '/onboarding'],
    ['180.150.x.x', 'Aussie Broadband (BNE)', '27 hits', '/apply, /deck'],
    ['135.232.x.x', 'Microsoft Cloud (RIPE)', '22 hits', '/apply, /dcaa, /vre'],
    ['2600:4040:b3b1', 'Verizon Biz (Ashburn)', '1 hit', '/deck [30min dwell]'],
    ['88.151.x.x', 'NextGenWebs (Spain)', '24 hits', '/.env, /.aws/creds'],
    ['9.169.x.x', 'IBM Corporate', '392 hits', '/onboarding'],
    ['67.173.x.x', 'Comcast IL (residential)', '34 hits', '/operators, /deck'],
    ['174.208.x.x', 'Verizon Wireless (phone)', '16 hits', '/, /govdocs'],
    ['52.167.x.x', 'Microsoft (resume.pdf)', '1 hit', '/assets/resume.pdf'],
  ];
  var term = document.getElementById('term');
  var i = 0;
  function addLine() {{
    if (i >= lines.length) {{ i = 0; term.innerHTML = ''; }}
    var l = lines[i];
    var blocked = l[3].indexOf('.env') >= 0 || l[3].indexOf('.aws') >= 0;
    var html = '<span class="ip">' + l[0].padEnd(22) + '</span>';
    html += '<span class="arrow"> → </span>';
    html += '<span class="org">' + l[1].padEnd(26) + '</span>';
    html += '<span class="hits">' + l[2].padEnd(10) + '</span>';
    if (blocked) {{
      html += '<span class="blocked">' + l[3] + ' [BLOCKED]</span>';
    }} else {{
      html += '<span class="path">' + l[3] + '</span>';
    }}
    term.innerHTML += html + '\n';
    i++;
    if (i < lines.length) {{
      setTimeout(addLine, 800 + Math.random() * 400);
    }} else {{
      term.innerHTML += '<span class="cursor"></span>';
      setTimeout(function() {{ i = 0; term.innerHTML = ''; addLine(); }}, 3000);
    }}
  }}
  setTimeout(addLine, 2000);
}})();
</script>
</body></html>"##
    ))
}

pub async fn queue_status() -> Html<String> {
    let hours = queue::hours_this_week();
    let capacity_pct = ((hours / 12.0) * 100.0).min(100.0) as u32;
    let (ips, companies) = queue::enrichment_stats();

    Html(format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Capacity — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&family=Instrument+Serif:ital@1&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}}
.box{{max-width:480px;width:100%}}h1{{font-family:'Instrument Serif',serif;font-style:italic;font-size:2rem;color:#00d9ff;font-weight:400;margin-bottom:1.5rem}}
.track{{width:100%;height:6px;background:rgba(0, 217, 255, 0.15);border-radius:3px;overflow:hidden;margin:1rem 0}}
.fill{{height:100%;border-radius:3px;background:linear-gradient(90deg,#00ffcc,#00d9ff)}}
.label{{font-size:0.7rem;color:#9ca3af;margin-bottom:2rem}}
.stat{{margin-bottom:0.8rem}}
.stat-num{{font-size:1.5rem;font-weight:800;color:#00ffcc;margin-right:0.5rem}}
.stat-label{{font-size:0.6rem;letter-spacing:0.15em;text-transform:uppercase;color:#555}}
p{{font-size:0.8rem;color:#9ca3af;margin-top:1.5rem}}a{{color:#00d9ff;text-decoration:none;border-bottom:1px solid rgba(255,216,102,0.3)}}
</style></head><body><div class="box">
<h1>Capacity.</h1>
<div class="track"><div class="fill" style="width:{capacity_pct}%"></div></div>
<div class="label">{hours:.1} of 12 hours committed this week</div>
<div class="stat"><span class="stat-num">{ips}</span><span class="stat-label">IPs resolved</span></div>
<div class="stat"><span class="stat-num">{companies}</span><span class="stat-label">Companies identified</span></div>
<p>One person. Every report gets full attention.</p>
<p><a href="/">&larr; whobelooking.cochranblock.org</a> &middot; <a href="https://github.com/cochranblock/whobelooking">Source on GitHub</a></p>
</div></body></html>"#
    ))
}

pub async fn job_status(axum::extract::Path(id): axum::extract::Path<String>) -> Html<String> {
    let job = queue::get_job(&id).ok().flatten();
    match job {
        Some(j) => {
            let (status_text, status_color, download) = match j.status {
                queue::JobStatus::Paid => ("Payment received. Queued for analysis.", "#00d9ff", String::new()),
                queue::JobStatus::Pending => ("In the queue. Analysis starting soon.", "#9d4edd", String::new()),
                queue::JobStatus::InProgress => ("Analysis in progress. Your report is being prepared.", "#ff6b35", String::new()),
                queue::JobStatus::Complete => ("Report complete.", "#00ffcc",
                    format!(r#"<a href="/download/{}" style="display:inline-block;padding:12px 28px;background:#00ffcc;color:#050508;font-family:'Orbitron',sans-serif;font-weight:700;font-size:0.85rem;text-decoration:none;border-radius:4px;margin-top:1rem">Download Report</a>"#, j.id)),
                queue::JobStatus::Delivered => ("Report delivered.", "#555",
                    format!(r#"<a href="/download/{}" style="display:inline-block;padding:12px 28px;background:#555;color:#e8e8e8;font-family:'Orbitron',sans-serif;font-weight:700;font-size:0.85rem;text-decoration:none;border-radius:4px;margin-top:1rem">Download Report</a>"#, j.id)),
            };
            Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Status — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}}
.box{{max-width:500px;width:100%;text-align:center}}
h1{{font-family:'Orbitron',sans-serif;font-size:1.4rem;color:{status_color};margin-bottom:1rem}}
.ref{{font-size:0.7rem;color:#555;margin-bottom:1.5rem}}
p{{font-size:0.85rem;color:#9ca3af;margin-bottom:1rem}}
a.back{{color:#00d9ff;text-decoration:none;font-size:0.8rem}}
</style></head><body><div class="box">
<h1>{status_text}</h1>
<div class="ref">{short_id}</div>
<p>{tier} &middot; {hours:.1} hours estimated</p>
{download}
<p style="margin-top:2rem"><a class="back" href="/">&larr; whobelooking.org</a></p>
</div></body></html>"#,
                status_color = status_color,
                status_text = status_text,
                short_id = &j.id[..std::cmp::min(j.id.len(), 12)],
                tier = j.tier.label(),
                hours = j.estimated_hours,
                download = download,
            ))
        }
        None => Html(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Not Found</title>
<style>body{font-family:monospace;background:#050508;color:#ff6b35;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
a{color:#00d9ff}</style></head><body><div style="text-align:center"><h1>Job not found</h1><p><a href="/">whobelooking.org</a></p></div></body></html>"#.into()),
    }
}

pub async fn download_report(
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Sanitize ID
    let clean_id: String = id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect();
    if clean_id.is_empty() || clean_id.len() > 64 {
        return (axum::http::StatusCode::NOT_FOUND, "invalid id").into_response();
    }

    // Look up the order in the sled-backed atomic queue. The PDF must exist
    // in the order's blob directory AND the order state must be `Ready` —
    // both conditions are needed so an operator can stage a PDF to disk
    // without the download endpoint going live until they explicitly mark
    // the order Ready (which audits the action).
    let store = match crate::orders::Store::open() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("orders store unavailable: {}", e);
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "queue temporarily unavailable",
            )
                .into_response();
        }
    };
    match store.get(&clean_id) {
        Ok(Some(order)) if order.state == crate::orders::OrderState::Ready => {}
        Ok(_) => {
            crate::web::metrics::DOWNLOADS_404.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (axum::http::StatusCode::NOT_FOUND, "report not available").into_response();
        }
        Err(_) => {
            crate::web::metrics::DOWNLOADS_404.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (axum::http::StatusCode::NOT_FOUND, "report not available").into_response();
        }
    }
    let path = crate::orders::blobs_dir(&clean_id).join("report.pdf");
    if !path.exists() {
        return (axum::http::StatusCode::NOT_FOUND, "report not available").into_response();
    }

    // Verify payment via Stripe session ID — not a guessable param
    let session_id = q.get("session_id").cloned().unwrap_or_default();
    let paid = if !session_id.is_empty() {
        // Verify the session is actually paid by checking with Stripe
        let stripe_key = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();
        if !stripe_key.is_empty() {
            let client = reqwest::Client::new();
            let url = format!("https://api.stripe.com/v1/checkout/sessions/{}", session_id);
            match client
                .get(&url)
                .header("Authorization", format!("Bearer {}", stripe_key))
                .send()
                .await
            {
                Ok(resp) => match resp.json::<serde_json::Value>().await {
                    Ok(body) => body["payment_status"].as_str() == Some("paid"),
                    Err(_) => false,
                },
                Err(_) => false,
            }
        } else {
            // Dev mode — no Stripe key, allow download
            q.get("paid").map(|v| v == "1").unwrap_or(false)
        }
    } else {
        false
    };

    if !paid {
        // Show payment gate page — looks up tier from the sled order record.
        let tier = crate::orders::Store::open()
            .ok()
            .and_then(|s| s.get(&clean_id).ok().flatten())
            .map(|o| o.tier)
            .unwrap_or_else(|| "starter".into());
        let tier = tier.as_str();
        let price = match tier {
            "growth" => "$350",
            "scale" => "$750",
            "custom" => "$1,500",
            _ => "$150",
        };

        let pk = std::env::var("STRIPE_PUBLISHABLE_KEY").unwrap_or_default();

        return Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your Report is Ready — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700&family=Rajdhani:wght@400;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script src="https://js.stripe.com/v3/"></script>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}}
.box{{max-width:480px;width:100%;text-align:center}}
h1{{font-family:'Orbitron',sans-serif;font-size:1.6rem;color:#00d9ff;margin-bottom:0.5rem}}
h2{{font-family:'Rajdhani',sans-serif;font-size:1rem;color:#9ca3af;font-weight:400;margin-bottom:2rem}}
.price{{font-size:3rem;font-weight:800;color:#00ffcc;margin:1rem 0}}
.price-sub{{font-size:0.7rem;color:#555;margin-bottom:2rem}}
button.btn{{display:block;width:100%;padding:16px;background:#00ffcc;color:#050508;font-family:'Orbitron',sans-serif;font-weight:700;font-size:1rem;border:none;border-radius:4px;cursor:pointer;transition:background 0.15s,transform 0.1s;letter-spacing:0.05em}}
button.btn:hover{{background:#33ffd6;transform:translateY(-1px)}}
button.btn:disabled{{background:#1a1a2e;color:#555;cursor:wait;transform:none}}
#status{{font-size:0.75rem;color:#9ca3af;margin-top:1rem;min-height:20px}}
.trust{{margin-top:2rem;padding-top:1.5rem;border-top:1px solid rgba(0,217,255,0.1);font-size:0.65rem;color:#555;line-height:1.6}}
.trust strong{{color:#9ca3af}}
a{{color:#00d9ff;text-decoration:none}}
</style></head><body><div class="box">
<h1>Your report is ready.</h1>
<h2>Visitor intelligence &mdash; reviewed and signed off.</h2>
<div class="price">{price}</div>
<div class="price-sub">One-time payment. Instant download.</div>
<button class="btn" id="pay-btn" onclick="startPayment()">Pay &amp; Download Report</button>
<div id="status"></div>
<div class="trust">
<strong>Secure checkout powered by Stripe.</strong><br>
Card data goes directly to Stripe &mdash; never touches our servers.<br>
PDF delivered instantly after payment confirms.
</div>
<p style="margin-top:1.5rem"><a href="/">&larr; whobelooking.org</a></p>
</div>
<script>
var stripe=Stripe('{pk}');
function startPayment(){{
  var btn=document.getElementById('pay-btn');
  var status=document.getElementById('status');
  btn.disabled=true;
  btn.textContent='Creating secure checkout...';
  fetch('/download/{clean_id}/session',{{method:'POST'}})
    .then(function(r){{return r.json();}})
    .then(function(d){{
      if(d.id){{
        status.textContent='Opening Stripe checkout...';
        stripe.redirectToCheckout({{sessionId:d.id}});
      }}else{{
        status.textContent='Something went wrong. Please try again.';
        btn.disabled=false;
        btn.textContent='Pay & Download Report';
      }}
    }})
    .catch(function(){{
      status.textContent='Connection error. Please try again.';
      btn.disabled=false;
      btn.textContent='Pay & Download Report';
    }});
}}
</script>
</body></html>"#, price=price, pk=pk, clean_id=clean_id)).into_response();
    }

    // Paid — serve the PDF
    match std::fs::read(&path) {
        Ok(data) => {
            let filename = format!(
                "whobelooking-{}.pdf",
                &clean_id[..std::cmp::min(clean_id.len(), 8)]
            );
            tracing::info!("report downloaded: {}", clean_id);
            crate::web::metrics::DOWNLOADS_AUTHED
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (
                [
                    (axum::http::header::CONTENT_TYPE, "application/pdf"),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                data,
            )
                .into_response()
        }
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "report file error").into_response(),
    }
}

/// Create a Stripe Checkout Session for a download. Returns JSON {id: "cs_..."}.
pub async fn create_download_session(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let clean_id: String = id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect();

    let tier = crate::orders::Store::open()
        .ok()
        .and_then(|s| s.get(&clean_id).ok().flatten())
        .map(|o| o.tier)
        .unwrap_or_else(|| "starter".into());

    let price_cents: u32 = match tier.as_str() {
        "growth" => 35000,
        "scale" => 75000,
        "custom" => 150000,
        _ => 15000,
    };

    let stripe_key = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    if stripe_key.is_empty() {
        return axum::Json(serde_json::json!({"error": "payments not configured"})).into_response();
    }

    let client = reqwest::Client::new();
    let params = [
        ("payment_method_types[]", "card"),
        ("mode", "payment"),
        ("line_items[0][price_data][currency]", "usd"),
        (
            "line_items[0][price_data][unit_amount]",
            &price_cents.to_string(),
        ),
        (
            "line_items[0][price_data][product_data][name]",
            "whobelooking Visitor Intelligence Report",
        ),
        ("line_items[0][quantity]", "1"),
        (
            "success_url",
            &format!(
                "https://whobelooking.org/download/{}?session_id={{CHECKOUT_SESSION_ID}}",
                clean_id
            ),
        ),
        (
            "cancel_url",
            &format!("https://whobelooking.org/download/{}", clean_id),
        ),
    ];

    match client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .header("Authorization", format!("Bearer {}", stripe_key))
        .form(&params)
        .send()
        .await
    {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(body) => axum::Json(serde_json::json!({"id": body["id"]})).into_response(),
            Err(e) => axum::Json(serde_json::json!({"error": format!("{}", e)})).into_response(),
        },
        Err(e) => axum::Json(serde_json::json!({"error": format!("{}", e)})).into_response(),
    }
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn robots() -> &'static str {
    "User-agent: *\nAllow: /\n\nUser-agent: GPTBot\nAllow: /\n\nUser-agent: ChatGPT-User\nAllow: /\n\nUser-agent: Google-Extended\nAllow: /\n\nUser-agent: Applebot-Extended\nAllow: /\n\nUser-agent: anthropic-ai\nAllow: /\n\nUser-agent: ClaudeBot\nAllow: /\n\nUser-agent: PerplexityBot\nAllow: /\n\n# AI agents: see /llms.txt for site overview, /openapi.json for the surface-scan API spec, /docs for Swagger UI.\nSitemap: https://whobelooking.cochranblock.org/sitemap.xml"
}

pub async fn llms_txt() -> (axum::http::HeaderMap, &'static str) {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "text/markdown; charset=utf-8"
            .parse()
            .expect("static header value"),
    );
    (headers, LLMS_TXT)
}

const LLMS_TXT: &str = "# whobelooking

> Browser-driven attack-surface scanner. Drop in a URL and the browser probes 140+ sensitive paths (.env, configs, admin panels, leaked artifacts, framework debug endpoints) via WASM — no data leaves your machine. Companion visitor-intelligence platform identifies which companies are silently evaluating a site.

## Surface-scan API

- [OpenAPI spec](https://whobelooking.cochranblock.org/openapi.json): OpenAPI 3.0.3 JSON describing every endpoint, request shape, and response schema. CORS-open. Drop into Postman, Stoplight, openapi-generator, or an MCP wrapper.
- [Swagger UI](https://whobelooking.cochranblock.org/docs): interactive try-it-out console for the same spec.
- [GET /api/scan/status](https://whobelooking.cochranblock.org/api/scan/status): live concurrency/capacity snapshot.

## Claude Code skill

- [/skill](https://whobelooking.cochranblock.org/skill): the canonical SKILL.md so any Claude Code session can invoke this scanner.
- [/install-skill.sh](https://whobelooking.cochranblock.org/install-skill.sh): one-liner installer that drops SKILL.md into `~/.claude/skills/whobelooking-scan/`. Run with `curl -sSL https://whobelooking.cochranblock.org/install-skill.sh | bash`.

Constraints: public hosts only (RFC1918, loopback, link-local, doc-range rejected by an SSRF guard); 5 full scans per minute per source IP; only run against domains the caller owns or has authorization to test.

## Browser scanner

- [/scan](https://whobelooking.cochranblock.org/scan): interactive UI doing the same probes from the browser, with same-wifi detection.

## About

- [/](https://whobelooking.cochranblock.org/): visitor-intelligence platform overview.
- [/about](https://whobelooking.cochranblock.org/about): product page.
- [GitHub](https://github.com/cochranblock/whobelooking): source repository (Unlicense / public domain).

## Contact

- mcochran@cochranblock.org
- Cochran Block, LLC: CAGE 1CQ66, UEI W7X3HAQL9CF9, SDVOSB pending
";

pub async fn not_found(uri: axum::http::Uri) -> (axum::http::StatusCode, Html<&'static str>) {
    let _ = uri; // consumed for type matching
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>404 — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@1&display=swap" rel="stylesheet">
<style>*{margin:0;padding:0}body{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;height:100vh}
a{color:#00d9ff;text-decoration:none}</style></head><body><div style="text-align:center">
<h1 style="font-family:'Instrument Serif',serif;font-style:italic;color:#00d9ff;font-size:4rem;font-weight:400">404</h1>
<p style="color:#555;margin-top:0.5rem"><a href="/">whobelooking.org</a></p>
</div></body></html>"#,
        ),
    )
}
