"""Local HTML report generation with escaped, evidence-only content."""

from __future__ import annotations

import html
import base64
from collections import Counter
from pathlib import Path

from .models import AssessmentResult


def render_html_report(result: AssessmentResult) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    counts = Counter(finding.severity for finding in result.findings)
    summary = "".join(f'<li><strong>{esc(severity.title())}:</strong> {counts.get(severity, 0)}</li>' for severity in ("critical", "high", "medium", "low", "informational"))
    findings_html: list[str] = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for finding in sorted(result.findings, key=lambda item: severity_order[item.severity]):
        affected = "".join(f"<li><code>{esc(url)}</code></li>" for url in finding.affected_endpoints)
        evidence = "".join(f"<li>{esc(item)}</li>" for item in finding.evidence)
        references = " · ".join(esc(item) for item in (finding.cwe, finding.owasp_reference) if item)
        findings_html.append(f"""
        <article class="finding">
          <div class="finding-heading"><h3>{esc(finding.title)}</h3>
          <span class="badge {esc(finding.severity)}">{esc(finding.severity.title())}</span></div>
          <p><strong>Status:</strong> {esc(finding.status)} · <strong>Confidence:</strong> {esc(finding.confidence)} · <strong>Category:</strong> {esc(finding.category)}</p>
          <p>{references}</p>
          <h4>Evidence</h4><ul>{evidence}</ul>
          <h4>Affected endpoints</h4><ul>{affected or '<li>Not available</li>'}</ul>
          <p><strong>Business impact:</strong> {esc(finding.business_impact)}</p>
          <p><strong>Recommendation:</strong> {esc(finding.recommendation)}</p>
          <p><strong>Retest:</strong> {esc(finding.retest_guidance)}</p>
        </article>""")

    pages_html = "".join(f"<tr><td><code>{esc(page.url)}</code></td><td>{esc(page.status_code if page.status_code is not None else 'n/a')}</td><td>{esc(page.title)}</td></tr>" for page in result.pages)
    screenshots: list[str] = []
    total_image_bytes = 0
    for page in result.pages:
        if not page.screenshot:
            continue
        path = Path(page.screenshot)
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
            if size > 2_000_000 or total_image_bytes + size > 16_000_000:
                continue
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
            total_image_bytes += size
            screenshots.append(f'<figure><img src="data:image/png;base64,{encoded}" alt="Browser screenshot for {esc(page.url)}"><figcaption>{esc(page.url)} · HTTP {esc(page.status_code if page.status_code is not None else "n/a")}</figcaption></figure>')
        except OSError:
            continue
    api_html = "".join(f"<li><code>{esc(url)}</code></li>" for url in result.api_endpoints)
    limitations = "".join(f"<li>{esc(item)}</li>" for item in result.limitations)
    started = result.started_at.isoformat()
    completed = result.completed_at.isoformat() if result.completed_at else "Incomplete"
    authorized_domains = "".join(f"<li><code>{esc(domain)}</code></li>" for domain in result.authorized_domains)
    path_prefixes = "".join(f"<li><code>{esc(prefix)}</code></li>" for prefix in result.allowed_url_prefixes)
    actions = "".join(f"<tr><td>{esc(item.timestamp.isoformat())}</td><td>{esc(item.event.replace('_', ' '))}</td><td><code>{esc(item.url or '—')}</code></td></tr>" for item in result.activity if item.event not in {"request_allowed", "request_blocked"})
    selected = "".join(f"<li><code>{esc(check)}</code></li>" for check in result.selected_checks) or "<li>No selected check metadata recorded.</li>"
    remediation = sorted({finding.recommendation for finding in result.findings})
    remediation_html = "".join(f"<li>{esc(item)}</li>" for item in remediation) or "<li>No remediation items were generated because no findings were produced from the available observations.</li>"
    highest = next((severity for severity in ("critical", "high", "medium", "low", "informational") if counts.get(severity)), "none")
    browser_mode = "Headless Chromium" if result.browser_metadata.get("headless") else "Visible Chromium"
    environment = f"{result.browser_metadata.get('engine', 'Unavailable')} {result.browser_metadata.get('browser_version', '')}".strip()

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel AI Assessment {esc(result.assessment_id)}</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #18212f; background: #f4f6f9; }}
    body {{ max-width: 1080px; margin: 0 auto; padding: 36px 24px 64px; line-height: 1.5; }}
    h1, h2, h3 {{ line-height: 1.2; }} h1 {{ margin-bottom: 4px; }}
    .muted {{ color: #5a687a; }} .card, .finding {{ background: white; border: 1px solid #dce2ea; border-radius: 12px; padding: 20px; margin: 16px 0; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }}
    .meta div {{ overflow-wrap: anywhere; }} .badge {{ border-radius: 999px; padding: 3px 10px; background: #e8edf4; font-size: .85rem; }}
    .badge.high, .badge.critical {{ background: #ffe1df; color: #8b211a; }} .badge.medium {{ background: #fff0d0; color: #805500; }}
    .badge.low {{ background: #e1efff; color: #174d83; }} .finding-heading {{ display: flex; justify-content: space-between; gap: 16px; align-items: baseline; }}
    code {{ overflow-wrap: anywhere; }} table {{ width: 100%; border-collapse: collapse; }} th, td {{ border-bottom: 1px solid #e1e6ed; padding: 9px; text-align: left; vertical-align: top; }}
    figure {{ margin: 12px 0; padding: 12px; border: 1px solid #dce2ea; border-radius: 8px; background: #fbfcfe; }} figure img {{ width: 100%; max-height: 650px; object-fit: contain; }} figcaption {{ font-size: 12px; color: #5a687a; overflow-wrap: anywhere; margin-top: 6px; }}
    @media print {{ body {{ max-width: none; padding: 0; }} .card, .finding {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
  <header><p class="muted">Sentinel AI · Local browser assessment</p><h1>Assessment report</h1>
    <p class="muted">Assessment ID: {esc(result.assessment_id)} · Generated {esc(completed)}</p></header>
  <section class="card"><h2>1. Cover and assessment details</h2><div class="meta">
    <div><strong>Target</strong><br><code>{esc(result.target_url)}</code></div>
    <div><strong>Authorized by</strong><br>{esc(result.authorized_by)}</div>
    <div><strong>Authorization reference</strong><br>{esc(result.authorization_reference)}</div>
    <div><strong>Started</strong><br>{esc(started)}</div><div><strong>Completed</strong><br>{esc(completed)}</div>
    <div><strong>Browser mode</strong><br>{esc(browser_mode)}</div><div><strong>Worker</strong><br>{esc(result.worker_id)}</div>
  </div></section>
  <section class="card"><h2>2. Executive summary</h2>
    <p>Sentinel AI observed {len(result.pages)} page(s), {len(result.api_endpoints)} browser-visible API endpoint(s), and {len(result.findings)} potential or inconclusive finding(s). The highest observed severity was {esc(highest)}. This passive assessment does not establish full vulnerability coverage or prove a target secure.</p>
    <ul>{summary}</ul>
  </section>
  <section class="card"><h2>3. Target and authorization scope</h2>
    <p><strong>Authorized hosts:</strong></p><ul>{authorized_domains or '<li>Not recorded</li>'}</ul>
    <p><strong>Allowed URL prefixes:</strong></p><ul>{path_prefixes or '<li>All paths on authorized hosts</li>'}</ul>
    <p>Authorization: {esc(result.authorization_reference)} ({esc(result.authorized_by)}).</p>
  </section>
  <section class="card"><h2>4. Assessment methodology</h2><p>Assessment used {esc(browser_mode)} navigation within the explicitly registered host and URL scope. Same-scope pages were observed; forms and controls were not activated. Browser requests were paced and guarded, and passive response metadata was analyzed. Cookie values, request bodies, and query strings were not retained.</p></section>
  <section class="card"><h2>5. Testing environment</h2><div class="meta"><div><strong>Browser runtime</strong><br>{esc(environment)}</div><div><strong>Worker</strong><br>{esc(result.worker_id)}</div><div><strong>Pages observed</strong><br>{len(result.pages)}</div><div><strong>Browser-visible API endpoints</strong><br>{len(result.api_endpoints)}</div></div></section>
  <section class="card"><h2>6. Selected security checks</h2><ul>{selected}</ul><p>Check selection does not guarantee detection. Unsupported and active checks are outside this report's implemented coverage.</p></section>
  <section class="card"><h2>7. Scan timeline</h2><table><thead><tr><th>Time</th><th>Event</th><th>URL</th></tr></thead><tbody>{actions or '<tr><td colspan="3">No timeline events recorded.</td></tr>'}</tbody></table></section>
  <section class="card"><h2>8. Vulnerability summary</h2><p>{len(result.findings)} potential or inconclusive observations. Highest observed severity: {esc(highest)}.</p><ul>{summary}</ul></section>
  <section><h2>9. Detailed findings</h2>{''.join(findings_html) if findings_html else '<p>No findings were produced from the available observations. This is not proof that the website is secure.</p>'}</section>
  <section class="card"><h2>10. Evidence and screenshots</h2>{''.join(screenshots) if screenshots else '<p>No screenshot evidence was available or it exceeded the report embedding size limit.</p>'}</section>
  <section class="card"><h2>11. Risk assessment</h2><p>Observed findings are evidence-based passive indicators. Potential findings are not exploit verification; inconclusive observations require manual validation. Highest observed severity: {esc(highest)}.</p></section>
  <section class="card"><h2>12. Remediation recommendations</h2><ul>{remediation_html}</ul></section>
  <section class="card"><h2>13. Retesting guidance</h2><p>After remediation, repeat the assessment using the same authorized scope and compare the specific evidence. Independently validate any security control that this passive browser workflow cannot verify.</p></section>
  <section class="card"><h2>14. Limitations and exclusions</h2><ul>{limitations}</ul><p>No active testing, credentials, form submission, exploit payloads, TLS cipher audit, or authenticated access-control checks were performed.</p></section>
  <section class="card"><h2>15. Appendix: observed pages and browser-visible endpoints</h2><table><thead><tr><th>URL</th><th>Status</th><th>Title</th></tr></thead><tbody>{pages_html or '<tr><td colspan="3">No pages were observed.</td></tr>'}</tbody></table><h3>Browser-visible API endpoints</h3><ul>{api_html or '<li>None observed.</li>'}</ul></section>
</body></html>"""


def write_html_report(result: AssessmentResult, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html_report(result), encoding="utf-8")
    return destination
