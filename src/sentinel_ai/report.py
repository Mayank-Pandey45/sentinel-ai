"""Local HTML report generation with escaped, evidence-only content."""

from __future__ import annotations

import html
from collections import Counter
from pathlib import Path

from .models import AssessmentResult


def render_html_report(result: AssessmentResult) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    counts = Counter(finding.severity for finding in result.findings)
    summary = "".join(
        f'<li><strong>{esc(severity.title())}:</strong> {counts.get(severity, 0)}</li>'
        for severity in ("critical", "high", "medium", "low", "informational")
    )
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

    pages_html = "".join(
        f"<tr><td><code>{esc(page.url)}</code></td><td>{esc(page.status_code if page.status_code is not None else 'n/a')}</td><td>{esc(page.title)}</td></tr>"
        for page in result.pages
    )
    api_html = "".join(f"<li><code>{esc(url)}</code></li>" for url in result.api_endpoints)
    limitations = "".join(f"<li>{esc(item)}</li>" for item in result.limitations)
    started = result.started_at.isoformat()
    completed = result.completed_at.isoformat() if result.completed_at else "Incomplete"
    authorized_domains = "".join(f"<li><code>{esc(domain)}</code></li>" for domain in result.authorized_domains)
    path_prefixes = "".join(f"<li><code>{esc(prefix)}</code></li>" for prefix in result.allowed_url_prefixes)

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
    @media print {{ body {{ max-width: none; padding: 0; }} .card, .finding {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
  <header><p class="muted">Sentinel AI · Local browser assessment</p><h1>Assessment report</h1>
    <p class="muted">Assessment ID: {esc(result.assessment_id)}</p></header>
  <section class="card"><h2>Assessment details</h2><div class="meta">
    <div><strong>Target</strong><br><code>{esc(result.target_url)}</code></div>
    <div><strong>Authorized by</strong><br>{esc(result.authorized_by)}</div>
    <div><strong>Authorization reference</strong><br>{esc(result.authorization_reference)}</div>
    <div><strong>Started</strong><br>{esc(started)}</div><div><strong>Completed</strong><br>{esc(completed)}</div>
    <div><strong>Browser</strong><br>{esc(result.browser_metadata.get('engine', 'Unavailable'))} {esc(result.browser_metadata.get('browser_version', ''))}</div>
  </div></section>
  <section class="card"><h2>Executive summary</h2>
    <p>Sentinel AI observed {len(result.pages)} page(s), {len(result.api_endpoints)} browser-visible API endpoint(s), and {len(result.findings)} potential or inconclusive finding(s). This passive assessment does not establish full vulnerability coverage.</p>
    <ul>{summary}</ul>
  </section>
  <section><h2>Findings</h2>{''.join(findings_html) if findings_html else '<p>No findings were produced from the available observations.</p>'}</section>
  <section class="card"><h2>Scope and methodology</h2>
    <p><strong>Authorized hosts:</strong></p><ul>{authorized_domains or '<li>Not recorded</li>'}</ul>
    <p><strong>Allowed URL prefixes:</strong></p><ul>{path_prefixes or '<li>All paths on authorized hosts</li>'}</ul>
    <p>Assessment used visible Chromium navigation within the explicitly registered host and URL scope. Pages and same-scope links were observed; forms and controls were not activated. Network requests were paced and recorded as sanitized metadata, and passive response headers and cookie attributes were inspected. Cookie values, request bodies, and query strings were not retained.</p>
    <p>Authorization: {esc(result.authorization_reference)} ({esc(result.authorized_by)}).</p>
  </section>
  <section class="card"><h2>Observed pages</h2><table><thead><tr><th>URL</th><th>Status</th><th>Title</th></tr></thead><tbody>{pages_html or '<tr><td colspan="3">No pages were observed.</td></tr>'}</tbody></table></section>
  <section class="card"><h2>Browser-visible API endpoints</h2><ul>{api_html or '<li>None observed.</li>'}</ul></section>
  <section class="card"><h2>Limitations and retesting</h2><ul>{limitations}</ul><p>Retest after remediation using the same authorization boundaries and compare the observed response behavior.</p></section>
</body></html>"""


def write_html_report(result: AssessmentResult, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html_report(result), encoding="utf-8")
    return destination
