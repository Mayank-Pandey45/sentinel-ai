# Sentinel AI

Sentinel AI is a local, visible-browser MVP for bounded passive assessment of websites you own or have explicit authorization to assess. This repository implements **Phase 1 only**. It does not include an AI planner, OWASP ZAP, API control plane, Supabase, or a dashboard.

## Phase 1 features

- Visible Chromium via Playwright (`headless=False` by default).
- Required, expiring authorization record with exact host allowlist and optional URL path prefixes.
- DNS resolution checks on every intercepted HTTP(S) request; private, loopback, link-local, reserved, and non-public destinations are denied by default. Loopback is available only for an explicit local fixture authorization; metadata/link-local addresses remain blocked.
- Request routing validates redirects and subresources, rejects out-of-scope URLs, blocks non-GET/HEAD methods, downloads, WebSockets, EventSource, and common state-changing URL patterns.
- Bounded same-scope link discovery, screenshots, page metadata, forms, controls, and sanitized XHR/fetch endpoint inventory. The crawler never clicks controls or submits forms.
- Request pacing, page/depth/request limits, navigation timeouts, and a total run deadline.
- Passive observations of response security headers, session-like cookie attributes, HTTP password forms, and visible CSRF token field clues. Findings are marked potential or inconclusive where the observation cannot verify a vulnerability.
- Structured local JSON/JSONL output and an escaped HTML assessment report; sanitized action events are also streamed to the terminal.
- Pause, resume, stop, and emergency-stop controls on `BrowserController` for future control surfaces.

## Environment and installation

The supported runtime is Python 3.12 or later. On Kali Linux with XFCE, open a terminal in this project and run:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m playwright install --with-deps chromium
```

Run the visible browser from an unlocked XFCE desktop session. Check that `echo "$DISPLAY"` prints a display value. Do not run the browser with `sudo`.

On Windows PowerShell, use `py -3.12 -m venv .venv`, `.\.venv\Scripts\Activate.ps1`, then `python -m pip install -e ".[dev]"` and `python -m playwright install chromium`. Headed Chromium must be launched from an interactive desktop session.

## Authorization and launch

Copy `examples/authorization.example.json` to a private local file, replace the operator, approval reference, expiry, and allowed host with current written authorization, and use an exact hostname. The sample uses `example.com` only as a placeholder. Do not add wildcards unless you have explicitly authorized each subdomain through `include_subdomains`.

```bash
cp examples/authorization.example.json authorization.json
nano authorization.json
sentinel-ai --target 'https://www.example.com/' --authorization-file authorization.json --output-dir artifacts/example-assessment
```

The authorization must be unexpired and the target host must match exactly. If `allowed_url_prefixes` is populated, the target and every discovered URL must also match one of those scheme/host/path prefixes. The CLI is always visible by default. The assessment writes `report.html`, `assessment.json`, `activity.jsonl`, and viewport screenshots below the selected output directory. The default pace is one intercepted request every 0.1 seconds; tune it only when the authorization and target owner permit.

## Isolated test application

The fixture binds only to `127.0.0.1` and returns static test content plus a harmless GET endpoint. It contains a form that Sentinel AI must observe but never submit.

Terminal 1:

```bash
python examples/test_app.py
```

Terminal 2:

```bash
cp examples/authorization.local.example.json authorization.local.json
sentinel-ai --target 'http://127.0.0.1:8000/' --authorization-file authorization.local.json --output-dir artifacts/local-fixture
```

This local authorization explicitly permits loopback so the fixture can be assessed. It does not permit private LAN, link-local, or cloud metadata destinations.

## Tests

```bash
python -m pytest
```

Tests cover authorization and URL policy, DNS rebinding-style mixed DNS answers, encoded path-prefix escapes, local-loopback opt-in, browser-route policy, passive evidence normalization, and HTML escaping. A local Chromium integration test checks page discovery, screenshots, endpoint inventory, and secret redaction. If Playwright or Chromium is unavailable, that test reports an explicit skip reason; treat the browser flow as unverified until it runs. If pytest is not installed, run the same `unittest` cases with `PYTHONPATH=src python -m unittest discover -s tests -v`. The local fixture can also be used for a manual visible-browser smoke test.

## Security boundaries and limitations

- The Playwright routing guard is useful defense-in-depth, but it is not an operating-system egress boundary. A DNS answer can change between the guard's lookup and Chromium's connection. Run assessments in a dedicated disposable VM/container and enforce outbound network policy at the host or network layer. Do not expose browser debugging or scanner management ports.
- Request starts are paced and total requests are capped, but a separate maximum in-flight request limit is not implemented yet.
- Page JavaScript executes to render pages and can make GET requests. Sentinel blocks non-GET/HEAD traffic and common state-changing URL patterns, but cannot prove that every GET is side-effect free. Use a test account and isolated data, and do not assess production systems unless your authorization explicitly covers this behavior.
- No login automation, authenticated crawling, exploit payloads, active vulnerability tests, port scans, or destructive actions are performed.
- TLS observations are limited to whether the page used HTTP or HTTPS and the observed HSTS header; cipher suites and certificate chain validation are not reported.
- Cookie values and request bodies are not recorded. URL query strings and fragments are omitted from stored endpoints; likely high-entropy path segments are redacted. Page titles, link labels, screenshots, and authorization metadata may still contain sensitive information.
- Passive checks can produce false positives and do not establish exploitability. Review each evidence item and validate findings safely before remediation or publication.
- PDF export, AI planning, ZAP passive scanning, FastAPI, PostgreSQL/Supabase, and the React dashboard belong to later phases.

## Next development step

Add a separately permissioned, policy-mediated AI planning layer that can propose only bounded read-only navigation actions, then add human approval gates and audit coverage before introducing any scanner or cloud worker.
