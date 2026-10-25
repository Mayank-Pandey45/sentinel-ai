# Sentinel AI implementation audit

**Audit date:** 2026-10-25
**Baseline commit:** `b04775e` (`Initial Sentinel AI Phase 1 implementation`)
**Repository state before application changes:** clean `main`, tracking `origin/main`

## Executive summary

The repository is a small Python Phase 1 command-line scanner, not a web application. It has a bounded Playwright crawler, scope/authorization models, passive checks, JSON/JSONL output, and a static HTML report. It has no dashboard, API server, persistent database, job queue, worker registration, user or organization authentication, AI provider, approval workflow, PDF report, or live browser stream. The fixture at `examples/test_app.py` is a deliberately simple HTML target used to verify the scanner; it is not the Sentinel AI interface.

The passive scanner is real and its local integration test passes when Playwright and Chromium are available. A manual headless run against the local fixture visited two pages and recorded three requests. The same environment failed to start headed Chromium with `BrowserType.launch: spawn UNKNOWN`; a headless launch succeeded. This establishes a host/runtime limitation for visible-browser acceptance here, not a verified Kali XFCE result.

## Repository map

| Area | Existing implementation | State |
|---|---|---|
| Frontend | None | No dashboard or browser UI |
| Backend/API | `src/sentinel_ai/cli.py` | CLI argument parsing only; no HTTP API |
| Authorization and URL policy | `models.py`, `scope.py` | Typed, expiring host/path authorization and DNS/IP checks; no persisted target registry or user approval flow |
| Browser worker | `browser.py` | One Playwright context per run; bounded same-scope GET/HEAD crawl; screenshots; local control methods |
| Passive analysis | `analysis.py` | HTTP, selected response headers, cookie attributes, password-form transport, and a CSRF-field clue |
| Persistence | JSON and JSONL written by the CLI/controller | No database, durable jobs, tenant data, or history index |
| Reporting | `report.py` | Escaped HTML report and JSON; no PDF, report history, or embedded screenshot gallery |
| AI | `.env.example` | No provider client, model configuration, planner, policy-mediated action loop, or AI audit events |
| Tests | `tests/` | 25 `unittest` cases; no API, auth, job, tenant, AI, or dashboard coverage |

There is no `AGENTS.md` in the repository or its parent project directories. `pyproject.toml` declares Pydantic and Playwright. FastAPI, Uvicorn, and Jinja2 happen to be importable in the current host Python but are not declared project dependencies; pytest, SQLAlchemy, and ReportLab are not installed in the normal host interpreter.

## Baseline verification

- `python -m unittest discover -s tests -v`: **25 passed**, including the headless Playwright integration test when temporary Playwright/Chromium dependencies were made available.
- The default interpreter run without those temporary dependencies: **24 passed, 1 skipped** (`test_browser_integration` skips because Playwright is absent from that interpreter path).
- Manual headless assessment of the isolated localhost fixture: **2 pages**, **3 requests**, **3 potential findings**, with JSON, JSONL, screenshots, and HTML output. No form was submitted.
- Headed Chromium launch on this Windows host: **failed** with `BrowserType.launch: spawn UNKNOWN`. The requested Kali Linux/XFCE worker environment is not available here, so visible rendering there remains unverified.
- `pytest` could not be used because it is not installed. The declared `unittest` suite ran instead.

## Findings and priority

### P0 — No product workflow or durable trust boundary

There is no dashboard, API, login, organization model, target registry, database, worker registration, or scan-job state machine. The current CLI trusts the supplied JSON authorization file, then writes local output. Metrics, scan history, target authorization, and audit logs cannot be derived from persisted records because those records do not exist.

**Acceptance criteria:** A local dashboard and typed API must derive overview counts only from persisted scans/findings; a target must have a valid, explicit authorization record before a job can start; jobs must persist state transitions and cancellation; every API path must enforce the supported authentication and ownership model. If multi-organization auth cannot be implemented safely in this repository, the application must remain loopback-only and state that limitation rather than imply SaaS isolation.

### P1 — Headed browser is not verified on the target worker

`BrowserController` defaults to `headless=False`, creates a fresh context for a run, and closes it after crawling. The browser, however, could not spawn headed on the current host. The CLI has no worker health/heartbeat or browser-connection status and cannot show screenshots/events live in a UI. Pause/resume/stop are in-process methods only; no API or job runner calls them. The controller never clicks or submits controls, which is a useful safe default.

**Acceptance criteria:** Keep visible Chromium as the local-development default; surface browser launch/navigation/crash errors as real job state; prove an actual visible browser on the configured local worker; persist screenshots and timestamped activity per scan; close browser context and process on completion/cancel; exercise pause/resume/stop and emergency stop against a running job. Do not label screenshots as a live stream.

### P1 — Authorization and network limits are local and incomplete for a service

The current guardian checks host allowlists, URL prefixes, DNS answers, and prohibited IP ranges before intercepted browser requests. Its documented DNS-rebinding time-of-check/time-of-use limitation remains, and the model checks expiry on construction rather than rechecking it throughout a long run. There is no ownership proof/authorization evidence workflow or user/organization enforcement. Loopback/private exceptions are fields in a JSON file.

**Acceptance criteria:** Validate URL syntax, redirects, final host, DNS, and scope server-side before queueing; recheck authorization expiry and scope during execution; fail closed on redirects and unsafe destinations; store authorization metadata/evidence with owner and scope; bind the local service to loopback until authentication and tenant isolation are implemented; document that application-level DNS checks are not a network egress firewall.

### P1 — Findings are intentionally passive, but the model/report need lifecycle and provenance

The current checks observe selected security headers on HTTPS documents, session-like cookie flags, password fields on HTTP pages, and whether a POST form exposes an obvious CSRF-named field. Results are potential/inconclusive; no active exploit checks run. `Finding` has no scan ID, detection timestamp, source/scanner field, false-positive/resolved state, or per-evidence reference. CORS, mixed content, dependency, access-control, and JavaScript observations are not currently analyzed.

**Acceptance criteria:** Preserve evidence-based passive behavior and statuses; attach findings to persisted scans with timestamp/source/evidence; include remediation and references only when justified; support false-positive/resolved lifecycle; clearly explain unsupported and disabled active checks; never imply selection guarantees detection. Active checks stay disabled unless authorization explicitly allows them and high-risk state changes have a separate approval gate.

### P1 — Report output is real but narrow

The report is a local static HTML summary with escaped content and the current scan’s findings. JSON and activity JSONL are written, but there is no PDF output, download endpoint, report history, scan timeline view, or screenshot rendering/gallery. The report’s methodology text always says visible Chromium even when a headless controller is used.

**Acceptance criteria:** Generate HTML and JSON from persisted observations/findings (including zero-finding scans); record correct browser mode; link evidence and screenshots safely; offer report history/download; either implement PDF or label it unavailable.

### P2 — No AI provider or bounded browser agent

There is no LLM integration, model configuration, observation sanitizer, action schema, policy engine, prompt-injection defense, approval queue, iteration/token limits, or agent memory. `.env.example` is only a note reserving space for future credentials.

**Acceptance criteria:** With no credentials, show **AI unavailable** and run deterministic passive checks. With a configured provider, parse a strict structured proposal and pass every action through an allowlist/scope/limit/cancellation policy before execution. Never give the model arbitrary shell, Python, JavaScript, or unrestricted HTTP tools. Strip secrets from observations; treat page content as untrusted; require human approval for login submissions and sensitive operations; record proposals, decisions, actions, and evidence references.

### P2 — Existing tests cover policy helpers, not the requested application workflow

The 25 passing tests cover URL/DNS policy, passive analysis, report escaping, route behavior, and one local headless browser integration. There are no tests for persistent jobs, API authorization, target validation/reachability, worker lifecycle, malformed AI output, prompt injection, approvals, tenant isolation, PDF, or UI accessibility/responsiveness.

**Acceptance criteria:** Add tests alongside each implemented layer: URL/SSRF/authorization failures; persistence and job transitions; API authentication/ownership; worker launch failure/crash/cancellation; policy rejection of unsafe or repeated AI proposals and prompt-injection text; findings and zero-finding reports; and end-to-end flow against the loopback fixture. Run the full available suite and report any host-only visible-browser limitations accurately.

## Implementation sequence

1. Retain and harden scope checks, findings provenance, and report correctness.
2. Add a local-only service boundary, persistent store, and real job lifecycle.
3. Rebuild the dashboard against real API state, with explicit empty/error/unavailable states.
4. Connect the local worker, live event stream, screenshots, and real controls; verify headed browser on the actual target desktop.
5. Add a strict optional provider client and policy-mediated AI proposal loop; keep deterministic scanning available with AI disabled.
6. Add report history/export and complete integration/security tests.

## Limitations for this implementation environment

This host is Windows, not Kali Linux/XFCE. No model credentials or provider endpoint are configured. The browser integration can run headless; headed Chromium did not spawn here. A production multi-user deployment requires a deliberate identity provider, organization ownership model, TLS, host/network egress controls, and operational review. These must not be represented as implemented merely by adding dashboard screens.

## Implementation status after the audit

The repository now keeps the existing CLI and adds a loopback dashboard/API rather than replacing the scanner. The new interface uses persisted records and explicitly shows unavailable capabilities. Core files added after the baseline audit are `api.py`, `auth.py`, `store.py`, `worker.py`, `target_validation.py`, `agent.py`, and packaged `static/` assets. Existing browser, model, and report components were extended. Startup and use instructions are in the repository README.

| Area | Implemented and verified | Still limited or unavailable |
|---|---|---|
| Dashboard and API | Responsive dark interface; all ten requested views; typed API; first-owner setup; signed session cookie; CSRF on mutations; organization-scoped records; same-origin SSE | One local workspace; no invitations or identity-provider flow; loopback deployment only |
| Targets and scope | HTTP(S) normalization; credentials/query rejection; registered authorization required before probing; DNS/IP scope policy; redirect checks; pinned HTTP reachability probes; expiry validation; loopback/private opt-in | Authorization is owner-attested with a stored reference, not independently verified; DNS checks are not a network firewall |
| Worker/browser | Persisted queued/validating/running/completed/paused/approval/failed/cancelled states; local heartbeat; real Playwright controller; screenshots; persisted events; pause/resume/stop controls; isolated contexts | One in-process worker; this Windows host could not spawn headed Chromium (`spawn UNKNOWN`); visible browser on Kali XFCE remains unverified; browser video streaming is not implemented |
| Checks/findings | Implemented header, cookie, transport, form, and same-scope page/XHR observations; per-scan finding IDs/provenance/status; unsupported checks disabled; active checks unavailable | CORS, mixed content, dependencies, authenticated workflows, access-control checks, active tests, ZAP, and complete OWASP coverage are not implemented |
| AI browser intelligence | Optional OpenAI-compatible provider; strict proposal schema; discovered-link policy; sensitive-path/repeat/iteration controls; limited sanitized observations; human approval path; no fabricated reasoning when provider is absent | No provider credentials are configured; real-provider behavior was not exercised end to end; no arbitrary code or HTTP tools |
| Reports | Persisted result-based HTML/PDF/JSON endpoints and report history; bounded screenshots embedded; zero-finding reports state that they do not prove security | PDF depends on a working local headless Playwright Chromium runtime |

## Post-implementation verification

- Full unit/integration suite: **44 tests passed** with the local test dependency path and elevated loopback/Chromium access.
- End-to-end local fixture flow: owner setup → authorization record → URL validation → real headless worker scan → persisted events/findings → screenshot endpoint → HTML/PDF/JSON export passed.
- Existing browser integration: headless Chromium discovered the local fixture without submitting its form or persisting the fixture secret.
- Additional coverage: malformed/repeated AI actions, target normalization, DNS failure, out-of-scope redirect, expired authorization, missing CSRF, disconnected worker, browser launch failure, pause/resume/emergency stop, and cross-organization record denial.
- `node --check` passed for dashboard JavaScript; Python compilation and `git diff --check` passed.
- The dashboard is running in this local task session at `http://127.0.0.1:4173/`. First-run owner setup remains for the user to complete.
