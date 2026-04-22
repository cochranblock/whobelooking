// All Rights Reserved — The Cochran Block, LLC
//! Pages for whobelooking.org — story first, sample report prominent, sell the feeling.

use axum::response::Html;
use crate::queue;

const DEMO_HTML: &str = include_str!("../../demo.html");

pub async fn demo() -> Html<&'static str> {
    Html(DEMO_HTML)
}

pub async fn index() -> Html<String> {
    let hours = queue::hours_this_week();
    let (ips, companies) = queue::enrichment_stats();
    let capacity_pct = ((hours / 12.0) * 100.0).min(100.0) as u32;

    Html(format!(r##"<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>whobelooking — Who's looking at your site?</title>
<meta name="description" content="Visitor intelligence. We tell you which companies are silently evaluating your site, which pages they read, and what it means. Starting at $150.">
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
  <p class="hero-sub">We tell you which companies are silently evaluating you. Which pages they read. How long they stayed. Whether they're a threat or an opportunity. Starting at $150.</p>
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
  <div class="section-label">Pricing</div>
  <h2>Scales with your traffic</h2>
  <p>More visitors = more IPs to resolve = more analysis time. Price reflects the work.</p>
  <div class="pricing">
    <div class="price-card featured">
      <div class="price-tier">Starter</div>
      <div class="price-amount">$150</div>
      <div class="price-ips">&lt;500 unique IPs</div>
      <div class="price-hours">~1.5 hrs</div>
    </div>
    <div class="price-card">
      <div class="price-tier">Growth</div>
      <div class="price-amount">$350</div>
      <div class="price-ips">500 &ndash; 2,000 IPs</div>
      <div class="price-hours">~3 hrs</div>
    </div>
    <div class="price-card">
      <div class="price-tier">Scale</div>
      <div class="price-amount">$750</div>
      <div class="price-ips">2,000 &ndash; 10,000 IPs</div>
      <div class="price-hours">~6 hrs</div>
    </div>
    <div class="price-card">
      <div class="price-tier">Custom</div>
      <div class="price-amount">$1,500+</div>
      <div class="price-ips">10,000+ IPs</div>
      <div class="price-hours">Quote</div>
    </div>
  </div>
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
  <a href="mailto:mcochran@cochranblock.org?subject=whobelooking%20report%20request" class="btn">Request a Report</a>
  <a href="/sample" class="btn btn-ghost">View Sample</a>
</div>

<div class="who">
  <strong>Michael Cochran</strong> &mdash; Army 17C, USCYBERCOM J38, 13 years defense &amp; enterprise. The person who caught Microsoft, Google, IBM, and the SEC visiting his site with zero marketing spend. The tool that caught them runs your report.
</div>

<div class="footer">
  All Rights Reserved &mdash; The Cochran Block, LLC &mdash; CAGE 1CQ66 &mdash; UEI W7X3HAQL9CF9<br>
  whobelooking v0.2.0
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
</body></html>"##))
}

pub async fn order_form() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Order — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Instrument+Serif:ital@1&display=swap" rel="stylesheet">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}
.box{max-width:480px;width:100%}h1{font-family:'Instrument Serif',serif;font-style:italic;font-size:2rem;color:#00d9ff;font-weight:400;margin-bottom:1.5rem}
p{margin-bottom:1rem;font-size:0.85rem;color:#9ca3af;line-height:1.6}a{color:#00d9ff;text-decoration:none;border-bottom:1px solid rgba(255,216,102,0.3)}a:hover{border-color:#00d9ff}
strong{color:#e8e8e8}
ul{margin:1rem 0 1.5rem 1.2rem;font-size:0.85rem;color:#9ca3af}li{margin-bottom:0.4rem}
.btn{display:inline-block;padding:10px 28px;background:#00d9ff;color:#050508;font-family:inherit;font-weight:700;font-size:0.85rem;text-decoration:none;border:none;margin-top:1rem;letter-spacing:0.05em}
</style></head><body><div class="box">
<h1>Request a report.</h1>
<p>Email <strong><a href="mailto:mcochran@cochranblock.org?subject=whobelooking%20report%20request">mcochran@cochranblock.org</a></strong> with:</p>
<ul>
<li>Your site URL</li>
<li>Source type — Cloudflare, access log, or CSV</li>
<li>Credentials or log file attached</li>
<li>Which tier fits — Starter ($150), Growth ($350), Scale ($750), or Custom</li>
</ul>
<p>You'll get a confirmation with a payment link and estimated delivery within 24 hours.</p>
<a href="mailto:mcochran@cochranblock.org?subject=whobelooking%20report%20request" class="btn">Send Request</a>
<p style="margin-top:2rem"><a href="/">&larr; whobelooking.org</a></p>
</div></body></html>"#)
}

pub async fn queue_status() -> Html<String> {
    let hours = queue::hours_this_week();
    let capacity_pct = ((hours / 12.0) * 100.0).min(100.0) as u32;
    let (ips, companies) = queue::enrichment_stats();

    Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
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
<p><a href="/">&larr; whobelooking.org</a> &middot; <a href="/order">Request a report</a></p>
</div></body></html>"#))
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn not_found(uri: axum::http::Uri) -> (axum::http::StatusCode, Html<&'static str>) {
    let _ = uri; // consumed for type matching
    (axum::http::StatusCode::NOT_FOUND,
    Html(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>404 — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@1&display=swap" rel="stylesheet">
<style>*{margin:0;padding:0}body{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;height:100vh}
a{color:#00d9ff;text-decoration:none}</style></head><body><div style="text-align:center">
<h1 style="font-family:'Instrument Serif',serif;font-style:italic;color:#00d9ff;font-size:4rem;font-weight:400">404</h1>
<p style="color:#555;margin-top:0.5rem"><a href="/">whobelooking.org</a></p>
</div></body></html>"#))
}
