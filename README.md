# Sentinel AI

Sentinel AI is a local browser security assessment workspace for sites you own or have explicit written authorization to assess. The dashboard, FastAPI service, SQLite database, and assessment worker run on the same computer. It is an early passive assessment MVP; it is not a hosted SaaS or a proof that a website is secure.

## What works

- Local dashboard with first-run owner setup, signed sessions, CSRF checks, organization-scoped API queries, and a loopback-only service.
- Persistent SQLite records for authorization targets, scan jobs and states, findings, screenshots, events, worker heartbeat, action approvals, and audit entries.
- URL normalization, explicit target authorization, DNS/IP scope checks, pinned HTTP reachability probes, redirect validation, and a separate authorization expiry check.
- One local Playwright worker. Visible Chromium is the default. Headless mode can be selected for environments where a desktop browser cannot launch.
- Per-scan browser contexts; same-scope bounded crawl; request pacing and limits; screenshots; sanitized network events; no form submission; and pause, resume, stop, and emergency-stop controls.
- Evidence-based passive observations for security headers, session-cookie attributes, transport, forms, and same-scope browser/API discovery.
- Optional structured AI navigation proposals. Actions are schema validated and policy checked; credentials, cookie values, form submission, arbitrary code, and arbitrary HTTP tools are not provided to the model.
- HTML, JSON, and PDF reports generated from the persisted result, including a report for zero-finding scans.

Unsupported checks are visibly disabled. Active testing is not implemented and remains unavailable. Selecting a check does not guarantee detection.

## Install

Python 3.12 or later is required. From PowerShell in the repository:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m playwright install chromium
```

On Kali Linux with a logged-in XFCE desktop, install Python and the browser system dependencies first, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m playwright install --with-deps chromium
```

Run the visible browser from the logged-in desktop session; do not run Chromium with `sudo`.

## Start the dashboard

```powershell
python -m sentinel_ai.server --host 127.0.0.1 --port 4173
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). On first launch the terminal prints a one-time bootstrap token. Enter it in the setup screen to create the local owner and workspace. The password must be at least 12 characters. The database and generated reports are stored under `artifacts/sentinel/` by default; this directory is ignored by Git.

To choose another local data directory, set `SENTINEL_DATA_DIR` before starting. Do not bind the dashboard to a LAN address: the app rejects non-loopback clients and the supported deployment is local-only.

## Try a local authorized fixture

In another terminal, start the included fixture if it is not already running:

```powershell
python examples/test_app.py
```

The fixture listens only on `127.0.0.1:8000`. In the dashboard:

1. Open **Authorized Targets** and add `http://127.0.0.1:8000/`.
2. Record the local test authorization reference and expiry; check the loopback option only for this fixture.
3. Open **New Assessment**, select that target, enter the same URL, then choose **Validate target**.
4. Select implemented passive checks and start the assessment. Visible Chromium is the default; enable headless mode if the browser window cannot launch in your environment.
5. Follow the persisted event timeline and screenshots in **Live Browser**, then download HTML, PDF, or JSON from **Reports**.

The sample site is only a local test fixture. Do not scan a third-party or production target unless the owner has authorized the exact host, path scope, test method, and assessment window.

## Optional AI provider

AI is off unless selected for a scan and configured in the server environment. Set these before starting the dashboard:

```powershell
$env:SENTINEL_AI_API_KEY = "your-provider-key"
$env:SENTINEL_AI_MODEL = "your-model-name"
# Optional; defaults to https://api.openai.com/v1
$env:SENTINEL_AI_BASE_URL = "https://your-openai-compatible-endpoint/v1"
python -m sentinel_ai.server
```

Provider endpoints must use HTTPS; plain HTTP is accepted only for a localhost endpoint. With no valid provider settings the dashboard reports **AI unavailable** and deterministic passive scanning still works. The provider receives limited observations such as sanitized same-scope URLs and form counts; it does not receive cookie values, passwords, form values, or raw page text. A model response is only a proposal, never a finding.

## Tests

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

The suite covers URL and authorization policy, SSRF-related IP rules, redirect scope, authentication and CSRF, tenant isolation, worker disconnection and failure, pause/resume/stop, bounded AI proposals and repeated actions, report escaping and zero findings, plus a headless end-to-end dashboard scan against the local fixture. Browser tests need Playwright Chromium installed. The visible window itself is not automated by the headless integration test.

## Runtime and security limits

- This implementation has one local organization and one in-process worker. There is no invitation flow, identity provider, distributed queue, remote worker registration, or organization-management UI.
- The dashboard serves local activity and screenshots, not a remote browser video stream. Visible Chromium opens on the worker computer (the same computer in this supported setup).
- Worker heartbeat confirms the local worker loop is alive; Chromium launch is proven only when a scan actually starts. Launch errors are persisted on the job.
- Authorization is a documented owner attestation plus a stored reference and scope; the app does not independently prove domain ownership or inspect the underlying client authorization document.
- Passive observations do not establish exploitability. Authentication flows, access-control boundaries, TLS cipher suites, dependency vulnerability matching, CORS analysis, mixed-content analysis, and OWASP ZAP are not implemented.
- No active exploit checks, form submission, credential use, destructive operation, port scan, or unrestricted model action is available.
- Playwright request policy is defense in depth, not an operating-system egress firewall. DNS can change between policy checks and the browser connection. Use a disposable VM/container with host/network egress restrictions for security assessments.
- Screenshots can contain sensitive client data. They and the SQLite database remain in the local data directory; protect that directory and remove it under your data-retention policy.
- The present Windows host previously failed to launch headed Chromium with `BrowserType.launch: spawn UNKNOWN`; headless Chromium passed. Visible-browser behavior must be verified on the intended desktop/worker.
- Before production use, add a reviewed identity and tenant model, hardened network egress, deployment secrets and encryption, operational monitoring, authorization evidence management, and a security review of the full application.
