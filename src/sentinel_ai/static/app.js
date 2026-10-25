(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch]));
  const fmtDate = value => value ? new Date(value).toLocaleString() : "—";
  const shortDate = value => value ? new Date(value).toLocaleDateString() : "—";
  const STATUS_LABEL = {queued:"Queued",validating:"Validating",running:"Running",paused:"Paused",waiting_approval:"Needs approval",completed:"Completed",failed:"Failed",cancelled:"Cancelled"};
  const SEVERITIES = ["critical","high","medium","low","informational"];
  const state = {csrf:"", user:null, view:"overview", dashboard:null, targets:[], scans:[], findings:[], checks:[], events:[], approvals:[], activeScan:null, stream:null, probe:null, filter:"all", refreshTimer:null};

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
    if (options.method && !["GET","HEAD"].includes(options.method.toUpperCase()) && state.csrf) headers.set("X-CSRF-Token", state.csrf);
    const response = await fetch(path, {...options, headers, credentials:"same-origin"});
    const type = response.headers.get("content-type") || "";
    const body = type.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) {
      const detail = body && typeof body === "object" ? body.detail : body;
      const msg = typeof detail === "string" ? detail : detail?.message || JSON.stringify(detail || `Request failed (${response.status})`);
      const error = new Error(msg); error.status = response.status; error.detail = detail; throw error;
    }
    return body;
  }

  function toast(message, kind = "") {
    const item = document.createElement("div"); item.className = `toast ${kind}`; item.textContent = message;
    $("#toast-region").append(item); setTimeout(() => item.remove(), 4200);
  }

  function shellVisible(visible) {
    $("#auth-screen").hidden = visible; $("#app-shell").hidden = !visible;
  }

  async function init() {
    $("#top-date").textContent = new Date().toLocaleDateString(undefined,{weekday:"short",month:"short",day:"numeric"});
    try {
      const authState = await api("/api/auth/state");
      if (authState.setup_required) return renderAuth("setup");
      const me = await api("/api/auth/me"); state.user = me;
      const csrfCookie = document.cookie.split("; ").find(x => x.startsWith("sentinel_csrf="));
      state.csrf = csrfCookie ? decodeURIComponent(csrfCookie.split("=").slice(1).join("=")) : "";
      enterApp();
    } catch (error) {
      if (error.status === 401) return renderAuth("login");
      renderFatal(error.message);
    }
  }

  function renderAuth(mode, errorText = "") {
    shellVisible(false); const setup = mode === "setup";
    $("#auth-screen").innerHTML = `<div class="auth-card">
      <a class="brand" href="#"><span class="brand-mark"><svg viewBox="0 0 32 32"><path d="M16 2 28 7v8c0 7.4-4.8 12.5-12 15C8.8 27.5 4 22.4 4 15V7l12-5Z"/><path d="m10.5 15.5 3.6 3.6 7.7-8"/></svg></span><span><strong>sentinel<span>.ai</span></strong><small>LOCAL SECURITY WORKSPACE</small></span></a>
      <div class="eyebrow">${setup ? "First-time setup" : "Welcome back"}</div><h1>${setup ? "Create your workspace" : "Sign in to Sentinel AI"}</h1>
      <p>${setup ? "This dashboard runs on your computer. Use the one-time bootstrap token printed in the server terminal to create the local owner account." : "Sign in to access your local assessment workspace."}</p>
      <form id="auth-form">${setup ? `<div class="field"><label class="field-label" for="bootstrap">One-time bootstrap token</label><input class="input" id="bootstrap" name="bootstrap_token" autocomplete="off" required></div><div class="field"><label class="field-label" for="org">Workspace name</label><input class="input" id="org" name="organization_name" value="Local Security Team" minlength="2" required></div>` : ""}
      <div class="field"><label class="field-label" for="email">Email</label><input class="input" id="email" name="email" type="email" autocomplete="username" required></div>
      <div class="field"><label class="field-label" for="password">Password ${setup ? "(12 characters minimum)" : ""}</label><input class="input" id="password" name="password" type="password" autocomplete="${setup?"new-password":"current-password"}" minlength="${setup?12:1}" required></div>
      ${errorText ? `<div class="auth-error">${escapeHtml(errorText)}</div>` : ""}<button class="button primary" type="submit" style="width:100%;justify-content:center;margin-top:5px">${setup ? "Create local workspace" : "Sign in"}<span>→</span></button>
      </form><p class="help-text" style="margin-top:17px">Loopback-only service · Passwords are stored as salted PBKDF2 hashes · No data is sent to a hosted dashboard.</p>
    </div>`;
    $("#auth-form").addEventListener("submit", async event => {
      event.preventDefault(); const data = Object.fromEntries(new FormData(event.currentTarget));
      const submit = $("button[type=submit]", event.currentTarget); submit.disabled = true; submit.textContent = setup ? "Creating workspace…" : "Signing in…";
      try {
        const result = await api(setup ? "/api/auth/setup" : "/api/auth/login", {method:"POST",body:JSON.stringify(data)});
        state.csrf = result.csrf_token; state.user = result.user; enterApp();
      } catch (error) { renderAuth(mode,error.message); }
    });
  }

  function renderFatal(message) {
    shellVisible(false); $("#auth-screen").innerHTML = `<div class="auth-card"><div class="eyebrow">Service unavailable</div><h1>Could not load Sentinel AI</h1><p>${escapeHtml(message)}</p><button class="button" onclick="location.reload()">Retry</button></div>`;
  }

  function enterApp() {
    shellVisible(true);
    $("#profile-email").textContent = state.user?.email || "Local user"; $("#profile-initial").textContent = (state.user?.email || "M")[0].toUpperCase();
    $("#logout-btn").onclick = logout; $("#refresh-btn").onclick = () => loadAll(true);
    $$(".nav-item").forEach(button => button.addEventListener("click", () => navigate(button.dataset.view)));
    window.addEventListener("hashchange", () => { const view = location.hash.slice(1); if (view && view !== state.view) navigate(view,false); });
    const initial = location.hash.slice(1); if (initial && $(`.nav-item[data-view="${initial}"]`)) state.view = initial;
    loadAll().then(() => renderView());
    clearInterval(state.refreshTimer); state.refreshTimer = setInterval(() => loadAll().then(() => { if (["overview","live","history","reports"].includes(state.view)) renderView(); }), 5000);
    renderView();
  }

  async function logout() {
    try { await api("/api/auth/logout",{method:"POST",body:"{}"}); } catch (_) {}
    state.csrf = ""; state.user = null; renderAuth("login");
  }

  function navigate(view, updateHash = true) {
    if (!$(`.nav-item[data-view="${view}"]`)) return;
    state.view = view; if (updateHash) history.replaceState(null,"",`#${view}`);
    $$(".nav-item").forEach(button => button.classList.toggle("active",button.dataset.view === view));
    $("#page-label").textContent = ({overview:"Overview",new:"New Assessment",live:"Live Browser",history:"Scan History",findings:"Vulnerabilities",reports:"Reports",targets:"Authorized Targets",agent:"Agent Configuration",settings:"Settings",audit:"Audit Logs"})[view] || "Overview";
    if (view === "live") connectLiveStream(); else closeLiveStream();
    renderView();
  }

  async function loadAll(showToast = false) {
    try {
      const [dashboard,targets,scans,findings,checks] = await Promise.all([
        api("/api/dashboard"),api("/api/targets"),api("/api/scans"),api("/api/findings"),api("/api/checks")
      ]);
      state.dashboard=dashboard; state.targets=targets; state.scans=scans; state.findings=findings; state.checks=checks.checks;
      $("#org-name").textContent = (state.user?.organization_id || "LOCAL").slice(0,8).toUpperCase();
      const connected = !!dashboard.worker.connected; $("#top-worker-dot").className = `status-dot ${connected?"good":"warn"}`;
      $("#top-worker-text").textContent = connected ? "Local worker connected" : "Worker disconnected";
      if (showToast) toast("Workspace data refreshed.","success");
    } catch(error) { if (error.status === 401) renderAuth("login"); else if(showToast) toast(error.message,"error"); }
  }

  function renderView() {
    const renderer = ({overview:renderOverview,new:renderNew,live:renderLive,history:renderHistory,findings:renderFindings,reports:renderReports,targets:renderTargets,agent:renderAgent,settings:renderSettings,audit:renderAudit})[state.view] || renderOverview;
    renderer();
  }

  function heading(eyebrow,title,description,action="") { return `<div class="page-heading"><div><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p>${description}</p></div>${action}</div>`; }
  function badge(status) { return `<span class="badge ${escapeHtml(status)}">${escapeHtml(STATUS_LABEL[status] || status)}</span>`; }
  function severityBadge(value) { return `<span class="badge ${escapeHtml(value)}">${escapeHtml(value)}</span>`; }
  function empty(text) { return `<div class="empty">${escapeHtml(text)}</div>`; }

  function renderOverview() {
    const d=state.dashboard, m=d?.metrics; if (!m) { $("#view").innerHTML=`${heading("LOCAL SECURITY OPERATIONS","Loading workspace…","Reading persisted scan and finding data.")}<div class="skeleton" style="height:100px"></div>`;return; }
    const worker=d.worker||{}; const recent=m.recent_assessments||[]; const counts=[m.critical_findings,m.high_findings,m.medium_findings,m.low_findings,m.informational_findings];
    $("#view").innerHTML=`${heading("LOCAL SECURITY OPERATIONS","Assessment overview","Monitor authorized assessments, observed risk and the local browser worker.",`<button class="button primary" data-action="new">＋ New assessment</button>`)}
      <div class="grid metrics-grid">
        ${metric("Total scans",m.total_scans,"All persisted assessments","◷")}${metric("Completed",m.completed_scans,"Finished assessments","✓","accent")}${metric("Running",m.running_scans,"Validating or active","◎")}${metric("Queued",m.queued_scans,"Waiting for the local worker","⌁")}
      </div>
      <div class="content-grid"><div>
        <section class="panel"><div class="panel-head"><h2>Recent assessments</h2><button class="link-button" data-action="history">View history →</button></div>
        ${recent.length ? `<div class="table-wrap"><table><thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Started</th><th></th></tr></thead><tbody>${recent.map(scan=>`<tr><td><div>${escapeHtml(scan.target_name)}</div><div class="mono truncate">${escapeHtml(scan.base_url)}</div></td><td>${badge(scan.status)}</td><td>${Number(scan.findings_count)||0}</td><td>${escapeHtml(shortDate(scan.created_at))}</td><td><button class="link-button" data-open-scan="${escapeHtml(scan.id)}">Open</button></td></tr>`).join("")}</tbody></table></div>`:empty("No assessments yet. Create an authorization record, validate its target and start your first scan.")}</section>
        <section class="panel"><div class="panel-head"><h2>Finding severity</h2><span class="subtle">Open persisted findings</span></div>${renderSeverityBars(counts)}</section>
      </div><div>
        <section class="panel"><div class="panel-head"><h2>Local worker</h2><span class="subtle">Heartbeat</span></div><div class="worker-panel"><span class="worker-icon">⌘</span><div class="worker-info"><strong>Browser assessment worker</strong><p>${escapeHtml(worker.mode||"local")} · ${worker.last_heartbeat?`Seen ${escapeHtml(fmtDate(worker.last_heartbeat))}`:"Waiting for heartbeat"}</p></div><span class="worker-status"><i class="status-dot ${worker.connected?"good":"warn"}"></i>${worker.connected?"Connected":"Offline"}</span></div><p class="help-text">Visible Chromium opens on this same computer. Browser pixels are not streamed to the dashboard; timestamped screenshots are shown here.</p></section>
        <section class="panel"><div class="panel-head"><h2>Recent reports</h2><button class="link-button" data-action="reports">All reports →</button></div>${m.recent_reports?.length?m.recent_reports.slice(0,5).map(report=>`<div class="summary-line"><span>${escapeHtml(report.target_name)}</span><strong>${escapeHtml(shortDate(report.completed_at))} · ${Number(report.findings_count)||0} findings</strong></div>`).join(""):empty("Completed assessments will appear here with HTML, JSON and PDF export options.")}</section>
        <div class="risk-callout">A passive assessment reports only what the selected browser checks observed. Zero findings do not prove that a target is secure.</div>
      </div></div>`;
    wireCommon();
  }

  function metric(name,value,sub,icon,extra="") { return `<article class="metric-card ${extra}"><div class="metric-top"><span>${name}</span><span>${icon}</span></div><div class="metric-value">${Number(value)||0}</div><div class="metric-foot">${sub}</div></article>`; }
  function renderSeverityBars(counts) { const max=Math.max(1,...counts); return `<div class="bar-list">${SEVERITIES.map((key,i)=>`<div class="bar-row"><span>${key[0].toUpperCase()+key.slice(1)}</span><div class="bar-track"><div class="bar-fill ${key}" style="width:${counts[i]/max*100}%"></div></div><strong>${counts[i]||0}</strong></div>`).join("")}</div>`; }

  function renderNew() {
    const checks=state.checks.filter(c=>c.implemented), targetOptions=state.targets.map(t=>`<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)} · ${escapeHtml(t.base_url)}</option>`).join("");
    $("#view").innerHTML=`${heading("ASSESSMENT WORKFLOW","New assessment","Validate the destination, confirm its registered authorization, then run bounded passive browser checks.")}
      <div class="assessment-layout"><div>
        <section class="assessment-card"><div class="step-label"><span class="step-number">1</span>Target and authorization</div>
          <label class="field-label" for="scan-url">Website URL</label><div class="field-row"><input id="scan-url" class="input" type="url" placeholder="https://client-example.com" autocomplete="url"><button class="button" id="validate-target">Validate target</button></div>
          <p class="help-text">Only HTTP and HTTPS are accepted. A URL is never probed until you select an existing target authorization record.</p>
          <div class="form-grid" style="margin-top:14px"><div class="field full"><label class="field-label" for="scan-target">Authorized target record</label><select class="select" id="scan-target"><option value="">Choose an authorized target…</option>${targetOptions}</select>${!state.targets.length?`<p class="help-text">No authorization on file. <button class="link-button" data-action="targets">Create an authorized target →</button></p>`:""}</div></div>
          <div id="probe-state" class="validation-state"><span class="state-icon">◉</span><span>Enter a URL and select its authorization record. Validation checks DNS, redirects, scope and reachability.</span></div>
        </section>
        <section class="assessment-card"><div class="check-header"><div class="step-label" style="margin:0"><span class="step-number">2</span>Select implemented checks</div><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><select class="select" id="check-preset" style="width:auto;padding:6px 8px"><option value="">Preset profile…</option><option value="all">Passive baseline</option><option value="discovery">Browser discovery only</option><option value="none">Clear selection</option></select><button class="link-button" id="select-all">Select all permitted</button><span class="subtle"> · </span><button class="link-button" id="clear-checks">Clear selection</button></div></div>
          <p class="help-text" style="margin:8px 0 13px">Selection controls which passive findings are generated. Unsupported checks remain disabled; active testing is off and is not available in this MVP.</p>
          <div class="check-grid">${checks.map(check=>`<label class="check-card enabled"><input type="checkbox" name="check" value="${escapeHtml(check.id)}" checked><span class="check-body"><strong>${escapeHtml(check.name)}</strong><p>${escapeHtml(check.description)}</p><span class="check-meta"><span>${escapeHtml(check.risk)} risk</span><span>·</span><span>${escapeHtml(check.intensity)}</span></span></span></label>`).join("")}${state.checks.filter(c=>!c.implemented).map(check=>`<label class="check-card disabled"><input type="checkbox" disabled><span class="check-body"><strong>${escapeHtml(check.name)}</strong><p>${escapeHtml(check.description)}</p><span class="check-meta"><span>${escapeHtml(check.risk)} risk</span><span>·</span><span>Unavailable</span></span></span></label>`).join("")}</div>
        </section>
        <section class="assessment-card"><div class="step-label"><span class="step-number">3</span>Browser and scan limits</div>
          <div class="config-grid"><div class="field"><label class="field-label" for="max-pages">Maximum pages</label><input class="input" id="max-pages" type="number" min="1" max="100" value="10"></div><div class="field"><label class="field-label" for="max-depth">Navigation depth</label><input class="input" id="max-depth" type="number" min="0" max="10" value="2"></div><div class="field"><label class="field-label" for="max-duration">Time limit (seconds)</label><input class="input" id="max-duration" type="number" min="5" max="3600" value="300"></div><div class="field"><label class="field-label" for="max-requests">Maximum requests</label><input class="input" id="max-requests" type="number" min="1" max="5000" value="500"></div><div class="field"><label class="field-label" for="request-delay">Request interval (seconds)</label><input class="input" id="request-delay" type="number" min="0" max="10" step="0.1" value="0.1"></div></div>
          <label class="toggle-row"><span class="toggle-label"><strong>Visible browser on this computer</strong><p>Default mode. The Chromium window opens locally; the dashboard shows screenshots and events, not a video stream.</p></span><input class="switch" id="headless-toggle" type="checkbox" aria-label="Use headless mode"></label>
          <label class="toggle-row"><span class="toggle-label"><strong>Capture screenshots</strong><p>Stored in this local workspace and available in the Live Browser view.</p></span><input class="switch" id="screenshots-toggle" type="checkbox" checked></label>
          <label class="toggle-row"><span class="toggle-label"><strong>AI browser proposals</strong><p id="ai-toggle-help">${state.dashboard?.ai_available?"Optional model proposals; every action is policy checked.":"AI unavailable — configure provider environment variables. Passive scanning remains available."}</p></span><input class="switch" id="ai-toggle" type="checkbox" ${state.dashboard?.ai_available?"":"disabled"}></label>
        </section>
      </div><aside class="side-summary"><section class="panel"><div class="panel-head"><h2>Assessment summary</h2><span class="badge warning">Passive</span></div><div class="summary-line"><span>Target state</span><strong id="summary-state">Not validated</strong></div><div class="summary-line"><span>Checks selected</span><strong id="summary-checks">${checks.length}</strong></div><div class="summary-line"><span>Browser</span><strong id="summary-browser">Visible Chromium</strong></div><div class="summary-line"><span>Worker</span><strong>${state.dashboard?.worker?.connected?"Connected":"Disconnected"}</strong></div><div class="summary-note">Start stays disabled until an in-scope URL is reachable, its authorization is current, a worker is connected, and at least one implemented check is selected.</div><button id="start-assessment" class="button primary" style="width:100%;justify-content:center;margin-top:14px" disabled>Start assessment <span>→</span></button><button class="button ghost" data-action="targets" style="width:100%;justify-content:center;margin-top:8px">Manage authorizations</button></section></aside></div>`;
    const checkboxes=$$("input[name=check]"); checkboxes.forEach(box=>box.addEventListener("change",updateAssessmentReadiness));
    $("#scan-url").addEventListener("input",()=>{state.probe=null;updateProbeState("Enter a URL and select its authorization record.","");updateAssessmentReadiness();});
    $("#scan-target").addEventListener("change",()=>{state.probe=null;updateProbeState("Target changed. Validate this URL against the selected authorization.","warning");updateAssessmentReadiness();});
    $("#validate-target").onclick=validateTarget;
    $("#select-all").onclick=()=>{checkboxes.filter(c=>!c.disabled).forEach(c=>c.checked=true);updateAssessmentReadiness();};
    $("#clear-checks").onclick=()=>{checkboxes.forEach(c=>c.checked=false);updateAssessmentReadiness();};
    $("#check-preset").onchange=event=>{const mode=event.target.value;checkboxes.forEach(c=>{c.checked=mode==="all"||(mode==="discovery"&&c.value==="browser_discovery");});event.target.value="";updateAssessmentReadiness();};
    $("#headless-toggle").onchange=()=>{$("#summary-browser").textContent=$("#headless-toggle").checked?"Headless Chromium":"Visible Chromium";};
    $("#start-assessment").onclick=startAssessment; wireCommon(); updateAssessmentReadiness();
  }

  function updateProbeState(text,kind) { const panel=$("#probe-state"); if(!panel)return; panel.className=`validation-state ${kind}`;panel.innerHTML=`<span class="state-icon">${kind==="success"?"✓":kind==="error"?"!":"◉"}</span><span>${escapeHtml(text)}</span>`; }
  function updateAssessmentReadiness() {
    const start=$("#start-assessment"); if(!start)return;
    const selected=$$("input[name=check]:checked").length; $("#summary-checks").textContent=selected;
    const ready=state.probe?.state==="reachable"&&state.dashboard?.worker?.connected&&selected>0;
    $("#summary-state").textContent=ready?"Ready":state.probe?.state||"Not validated"; start.disabled=!ready;
  }
  async function validateTarget() {
    const url=$("#scan-url").value.trim(), targetId=$("#scan-target").value;
    if(!url){updateProbeState("Enter an HTTP or HTTPS URL.","error");return;}
    updateProbeState("Validating syntax, authorization scope, DNS and redirect chain…","");$("#validate-target").disabled=true;
    try {
      state.probe=await api("/api/targets/validate",{method:"POST",body:JSON.stringify({url,target_id:targetId||null})});
      const p=state.probe;
      if(p.state==="reachable") updateProbeState(`AUTHORIZED · REACHABLE · HTTP ${p.status_code} · ${p.final_url||p.normalized_url}${p.redirect_chain?.length?` · ${p.redirect_chain.length} redirect(s)`:""} · ${state.targets.find(t=>t.id===p.target_id)?.name||"registered"}`,"success");
      else updateProbeState(`${String(p.state||"error").replaceAll("_"," ").toUpperCase()} · ${p.error||"The destination is not ready to scan."}`,p.state==="authorization_required"?"warning":"error");
    } catch(error){state.probe={state:"error"};updateProbeState(error.message,"error");}
    finally{$("#validate-target").disabled=false;updateAssessmentReadiness();}
  }
  async function startAssessment() {
    const checks=$$("input[name=check]:checked").map(box=>box.value); const targetId=$("#scan-target").value;
    const payload={target_id:targetId,target_url:$("#scan-url").value.trim(),selected_checks:checks,headless:$("#headless-toggle").checked,capture_screenshots:$("#screenshots-toggle").checked,ai_analysis:$("#ai-toggle").checked,limits:{max_pages:Number($("#max-pages").value),max_depth:Number($("#max-depth").value),max_duration_seconds:Number($("#max-duration").value),max_requests:Number($("#max-requests").value),request_delay_seconds:Number($("#request-delay").value),navigation_delay_seconds:.3,navigation_timeout_ms:20000}};
    const button=$("#start-assessment");button.disabled=true;button.textContent="Creating assessment…";
    try { const scan=await api("/api/scans",{method:"POST",body:JSON.stringify(payload)});state.activeScan=scan.id;await loadAll();navigate("live");toast("Assessment queued for the local worker.","success"); }
    catch(error){toast(error.message,"error");button.textContent="Start assessment →";updateAssessmentReadiness();}
  }

  function renderLive() {
    const active=state.scans.find(s=>["queued","validating","running","paused","waiting_approval"].includes(s.status));
    const scan=state.scans.find(s=>s.id===state.activeScan)||active||state.scans[0]; state.activeScan=scan?.id||null;
    if(!scan){$("#view").innerHTML=`${heading("BROWSER WORKSPACE","Live Browser","Follow the local worker’s timestamped activity and screenshots.")}<section class="panel">${empty("No assessment is queued or running. Start an authorized assessment to see browser activity here.")}<button class="button primary" data-action="new">Start an assessment →</button></section>`;wireCommon();return;}
    const ev=state.events.filter(event=>event.scan_id===scan.id||!event.scan_id);const latestShotEvent=[...ev].reverse().find(e=>(e.event==="page_observed"||e.event==="ai_action_executed")&&e.details?.screenshot);const latestShot=latestShotEvent?.details?.screenshot;
    const currentEvent=[...ev].reverse().find(e=>e.event==="page_observed"&&e.url);const worker=state.dashboard?.worker||{};
    const lastPage=scan.pages_count||ev.filter(e=>e.event==="page_observed").length;const requests=scan.requests_count||ev.filter(e=>e.event==="request_allowed").length;
    $("#view").innerHTML=`${heading("BROWSER WORKSPACE","Live Browser","Assessment " + escapeHtml(scan.id.slice(0,12)) + " · " + escapeHtml(scan.target_name||"Authorized target"),badge(scan.status))}
      <div class="live-layout"><div class="live-column"><section class="panel"><div class="panel-head"><h2>Assessment state</h2>${badge(scan.status)}</div>
        ${liveStat("Website",scan.config?.target_url||scan.base_url)}${liveStat("Scan ID",scan.id)}${liveStat("Phase",STATUS_LABEL[scan.status]||scan.status)}${liveStat("Worker",worker.connected?"Local worker connected":"Worker disconnected")}${liveStat("Current page",currentEvent?.url||scan.config?.target_url||"Waiting for navigation")}${liveStat("Elapsed",elapsed(scan.started_at,scan.completed_at))}${liveStat("Pages observed",lastPage)}${liveStat("Requests observed",requests)}${liveStat("Findings",state.findings.filter(f=>f.scan_id===scan.id).length)}
        <div class="live-controls">${scan.status==="running"?`<button class="button small" data-scan-control="pause">Ⅱ Pause</button>`:""}${scan.status==="paused"?`<button class="button small" data-scan-control="resume">▶ Resume</button>`:""}${["queued","validating","running","paused","waiting_approval"].includes(scan.status)?`<button class="button danger small" data-scan-control="stop">■ Stop</button><button class="button danger small" data-scan-control="emergency">Emergency stop</button>`:""}</div>
        ${scan.error?`<div class="validation-state error" style="margin-top:12px">${escapeHtml(scan.error)}</div>`:""}
      </section></div><div class="live-column"><section class="panel"><div class="panel-head"><h2>Local browser activity</h2><span class="badge">${scan.config?.headless?"Headless":"Visible desktop"} · ${escapeHtml(scan.config?.browser_channel||"chromium")}</span></div><div class="browser-stage">${latestShot?`<img src="/api/scans/${encodeURIComponent(scan.id)}/screenshots/${encodeURIComponent(latestShot)}?v=${Date.now()}" alt="Latest local browser screenshot"><p class="browser-caption">Latest screenshot · captured locally · ${escapeHtml(fmtDate(latestShotEvent?.timestamp))}</p>`:`<div class="browser-symbol">◉</div><h2>${scan.status==="queued"?"Waiting for browser worker":"No screenshot available yet"}</h2><p>${scan.config?.headless?"Headless Chromium is configured for this assessment.":"Visible Chromium runs on the local worker’s desktop. This dashboard does not stream browser video."}</p>`}</div>
        ${scan.status==="waiting_approval"?`<div class="risk-callout" style="margin-top:12px">An AI proposal needs human review. Open the event timeline for approval controls.</div>`:""}
        <div class="live-controls"><button class="button ghost small" data-refresh-scan="${escapeHtml(scan.id)}">↻ Refresh events</button>${scan.status==="completed"?`<a class="button small" href="/api/scans/${encodeURIComponent(scan.id)}/report.html" target="_blank">Open report</a>`:""}</div></section></div>
      <div class="live-column"><section class="panel"><div class="panel-head"><h2>Activity timeline</h2><span class="subtle">Persisted worker events</span></div>${state.approvals.length?`<div class="approval-list">${state.approvals.map(a=>`<div class="risk-callout" style="margin-bottom:10px"><strong>Review proposed ${escapeHtml(a.proposal.action)} action</strong><p>${escapeHtml(a.proposal.objective)} · ${escapeHtml(a.proposal.reason)}</p><div class="live-controls"><button class="button primary small" data-approval="${escapeHtml(a.id)}" data-approved="true">Approve</button><button class="button danger small" data-approval="${escapeHtml(a.id)}" data-approved="false">Reject</button></div></div>`).join("")}</div>`:""}<div id="live-events" class="event-list">${ev.length?ev.slice(-80).reverse().map(renderEvent).join(""):empty("Waiting for worker events…")}</div></section></div></div>`;
    wireCommon();$$('[data-scan-control]').forEach(button=>button.onclick=()=>scanControl(scan.id,button.dataset.scanControl));$$('[data-approval]').forEach(button=>button.onclick=()=>resolveApproval(button.dataset.approval,button.dataset.approved==="true",scan.id));const refresh=$("[data-refresh-scan]");if(refresh)refresh.onclick=async()=>{await loadAll();await loadScanEvents(scan.id);renderLive();};
    loadScanEvents(scan.id).then(()=>{if(state.view==="live")renderLive();});
  }
  function liveStat(label,value){return `<div class="live-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value??"—")}</strong></div>`;}
  function renderEvent(event){const detail=event.details||{};const title=event.event.replaceAll("_"," ");const allowed=detail.policy_allowed??detail.allowed;const sub=[event.url,detail.objective,detail.action&&`Action: ${detail.action}`,detail.target_id&&`Target: ${detail.target_id}`,allowed!==undefined&&`Policy: ${allowed?"allowed":"blocked"}`,detail.policy_reason,detail.reason,detail.expected_result,detail.destination&&`Destination: ${detail.destination}`,detail.actual_url&&`Actual: ${detail.actual_url}`,detail.verified!==undefined&&`Verified: ${detail.verified?"yes":"no"}`,detail.screenshot&&`Screenshot: ${detail.screenshot}`,detail.error,detail.error_type,detail.browser_mode,detail.browser_channel&&`Browser: ${detail.browser_channel}`,detail.chromium_sandbox!==undefined&&`Chromium sandbox: ${detail.chromium_sandbox?"on":"off"}`,detail.title&&`Finding: ${detail.title}`].filter(Boolean).join(" · ");return `<article class="event-item"><time>${escapeHtml(fmtDate(event.timestamp))}</time><strong>${escapeHtml(title)}</strong>${sub?`<p>${escapeHtml(sub)}</p>`:""}</article>`;}
  function elapsed(started,completed){if(!started)return "—";const seconds=Math.max(0,Math.floor(((completed?new Date(completed):new Date())-new Date(started))/1000));return `${Math.floor(seconds/60)}m ${seconds%60}s`;}
  async function loadScanEvents(scanId){try{const detail=await api(`/api/scans/${encodeURIComponent(scanId)}`);state.events=detail.events.map(e=>({...e,scan_id:scanId}));state.approvals=detail.approvals||[];state.activeScan=scanId;}catch(error){if(error.status!==404)toast(error.message,"error");}}
  function connectLiveStream(){closeLiveStream();const scan=state.scans.find(s=>s.id===state.activeScan)||state.scans.find(s=>["queued","validating","running","paused","waiting_approval"].includes(s.status));if(!scan)return;state.activeScan=scan.id;loadScanEvents(scan.id).then(renderLive);try{const source=new EventSource(`/api/scans/${encodeURIComponent(scan.id)}/events`,{withCredentials:true});state.stream=source;source.addEventListener("activity",event=>{try{const entry=JSON.parse(event.data);entry.scan_id=scan.id;state.events.push(entry);if(state.events.length>1000)state.events=state.events.slice(-800);if(state.view==="live")renderLive();}catch(_){}});source.addEventListener("done",()=>{loadAll().then(()=>renderLive());});}catch(_){} }
  function closeLiveStream(){if(state.stream){state.stream.close();state.stream=null;}}
  async function scanControl(id,action){try{const endpoint=action==="emergency"?`/api/scans/${id}/stop?emergency=true`:`/api/scans/${id}/${action}`;await api(endpoint,{method:"POST",body:"{}"});toast(action==="emergency"?"Emergency stop requested.":`Assessment ${action} requested.`,"success");await loadAll();await loadScanEvents(id);renderLive();}catch(error){toast(error.message,"error");}}
  async function resolveApproval(id,approved,scanId){try{await api(`/api/approvals/${encodeURIComponent(id)}`,{method:"POST",body:JSON.stringify({approved})});toast(approved?"Action approved.":"Action rejected.","success");await loadScanEvents(scanId);renderLive();}catch(error){toast(error.message,"error");}}

  function renderHistory(){const rows=state.scans;$("#view").innerHTML=`${heading("ASSESSMENT RECORDS","Scan history","Every row comes from a persisted local assessment job.",`<button class="button primary" data-action="new">＋ New assessment</button>`)}<section class="panel"><div class="panel-head"><h2>All assessments</h2><span class="subtle">${rows.length} stored</span></div>${rows.length?`<div class="table-wrap"><table><thead><tr><th>Assessment</th><th>Target</th><th>Status</th><th>Pages</th><th>Requests</th><th>Created</th><th>Report</th></tr></thead><tbody>${rows.map(s=>`<tr><td><button class="link-button mono" data-open-scan="${escapeHtml(s.id)}">${escapeHtml(s.id.slice(0,12))}</button></td><td><div>${escapeHtml(s.target_name||"")}</div><div class="mono">${escapeHtml(s.config?.target_url||s.base_url||"")}</div></td><td>${badge(s.status)}</td><td>${s.pages_count||0}</td><td>${s.requests_count||0}</td><td>${escapeHtml(fmtDate(s.created_at))}</td><td>${s.status==="completed"?reportLinks(s.id):"—"}</td></tr>`).join("")}</tbody></table></div>`:empty("No scan jobs have been saved yet.")}</section>`;wireCommon();}

  function renderFindings(){const rows=state.findings.filter(f=>state.filter==="all"||f.severity===state.filter);$("#view").innerHTML=`${heading("EVIDENCE-BASED RESULTS","Vulnerabilities","Potential and inconclusive observations from completed passive assessments. Update triage status as your team reviews evidence.")}<div class="filter-row"><button class="pill ${state.filter==="all"?"active":""}" data-filter="all">All (${state.findings.length})</button>${SEVERITIES.map(sev=>`<button class="pill ${state.filter===sev?"active":""}" data-filter="${sev}">${sev}</button>`).join("")}</div><section class="panel">${rows.length?`<div class="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Target page</th><th>Confidence</th><th>Source</th></tr></thead><tbody>${rows.map(f=>`<tr><td><strong>${escapeHtml(f.title)}</strong><div class="mono">${escapeHtml(f.category)} · ${escapeHtml(f.id)}</div></td><td>${severityBadge(f.severity)}</td><td><select class="select finding-status" data-finding="${escapeHtml(f.id)}" style="width:140px;padding:6px">${["potential","verified","inconclusive","false_positive","resolved"].map(s=>`<option value="${s}" ${f.status===s?"selected":""}>${s.replaceAll("_"," ")}</option>`).join("")}</select></td><td class="mono truncate">${escapeHtml(f.affected_endpoints?.[0]||"—")}</td><td>${escapeHtml(f.confidence)}</td><td>${escapeHtml(f.scanner)}</td></tr><tr><td colspan="6" style="padding-top:0;color:#8191a4;white-space:normal">${escapeHtml(f.evidence?.[0]||"")} <span style="color:#69cfc8">${escapeHtml(f.recommendation||"")}</span></td></tr>`).join("")}</tbody></table></div>`:empty("No findings match this view. Completed scans with zero observations are not proof of security.")}</section>`;wireCommon();$$('.finding-status').forEach(select=>select.onchange=async()=>{try{await api(`/api/findings/${encodeURIComponent(select.dataset.finding)}`,{method:"PATCH",body:JSON.stringify({status:select.value})});toast("Finding status updated.","success");await loadAll();renderFindings();}catch(error){toast(error.message,"error");}});$$('[data-filter]').forEach(button=>button.onclick=()=>{state.filter=button.dataset.filter;renderFindings();});}

  function reportLinks(id){return `<a class="link-button" href="/api/scans/${encodeURIComponent(id)}/report.html">HTML</a> · <a class="link-button" href="/api/scans/${encodeURIComponent(id)}/report.pdf">PDF</a> · <a class="link-button" href="/api/scans/${encodeURIComponent(id)}/report.json">JSON</a>`;}
  function renderReports(){const rows=state.scans.filter(s=>s.status==="completed");$("#view").innerHTML=`${heading("ASSESSMENT OUTPUT","Reports","Generate-on-request HTML, PDF and JSON exports from stored observations and findings.")}<section class="panel"><div class="panel-head"><h2>Completed assessment reports</h2><span class="subtle">${rows.length} available</span></div>${rows.length?`<div class="table-wrap"><table><thead><tr><th>Target</th><th>Completed</th><th>Findings</th><th>Pages</th><th>Formats</th></tr></thead><tbody>${rows.map(s=>`<tr><td><strong>${escapeHtml(s.target_name)}</strong><div class="mono">${escapeHtml(s.config?.target_url||s.base_url||"")}</div></td><td>${escapeHtml(fmtDate(s.completed_at))}</td><td>${state.findings.filter(f=>f.scan_id===s.id).length}</td><td>${s.pages_count}</td><td>${reportLinks(s.id)}</td></tr>`).join("")}</tbody></table></div>`:empty("A report is generated after a scan completes. HTML and JSON work without findings; PDF requires the local Playwright Chromium runtime.")}</section><div class="risk-callout">Reports summarize selected passive observations. An empty findings section does not establish that the target is secure or that all vulnerability classes were tested.</div>`;wireCommon();}

  function renderTargets(){const isOwner=state.user?.role==="owner";$("#view").innerHTML=`${heading("SCOPE AND AUTHORIZATION","Authorized targets","Register the exact approved URL scope and the client authorization record before probing. Authorization is a documented owner attestation; this app does not independently verify ownership.",isOwner?`<button class="button primary" id="add-target">＋ Add authorization</button>`:"")}
      <div class="risk-callout" style="margin-bottom:15px">Only targets with an explicit, current authorization record can be validated. Loopback/private network access is opt-in; link-local and cloud metadata addresses remain blocked. The local app is not a network egress firewall.</div>
      <div class="target-grid">${state.targets.length?state.targets.map(t=>`<article class="target-card"><div class="target-top"><div><h3>${escapeHtml(t.name)}</h3><p>${escapeHtml(t.base_url)}</p></div><span class="badge ${new Date(t.expires_at)>new Date()?"good":"failed"}">${new Date(t.expires_at)>new Date()?"Authorized":"Expired"}</span></div><div class="target-meta"><div>Authorized by <strong>${escapeHtml(t.authorized_by)}</strong></div><div>Reference <strong>${escapeHtml(t.authorization_reference)}</strong></div><div>Expires <strong>${escapeHtml(fmtDate(t.expires_at))}</strong></div><div>Added <strong>${escapeHtml(fmtDate(t.created_at))}</strong></div></div></article>`).join(""):empty("No targets have authorization records yet. Add a target with a documented scope and expiration date.")}</div>`;wireCommon();const add=$("#add-target");if(add)add.onclick=showTargetDialog;}

  function showTargetDialog(){const expires=new Date(Date.now()+90*86400000);expires.setMinutes(expires.getMinutes()-expires.getTimezoneOffset());const initial=expires.toISOString().slice(0,16);const modal=document.createElement("div");modal.className="modal-backdrop";modal.innerHTML=`<div class="auth-card" style="width:min(600px,100%);max-height:90vh;overflow:auto"><div class="eyebrow">Authorization record</div><h1>Register an authorized target</h1><p>Record the client-approved scope and expiry. Reachability does not grant authorization.</p><form id="target-form"><div class="form-grid"><div class="field"><label class="field-label">Target name</label><input class="input" name="name" placeholder="Client production site" required minlength="2"></div><div class="field"><label class="field-label">Base URL and path scope</label><input class="input" name="base_url" type="url" placeholder="https://client-example.com/app/" required></div><div class="field"><label class="field-label">Authorized by</label><input class="input" name="authorized_by" placeholder="Client contact or team" required minlength="2"></div><div class="field"><label class="field-label">Authorization reference</label><input class="input" name="authorization_reference" placeholder="Ticket, contract or approval ID" required minlength="2"></div><div class="field full"><label class="field-label">Authorization expires</label><input class="input" name="expires_at" type="datetime-local" value="${initial}" required></div></div><div style="display:grid;gap:11px;margin:14px 0"><label class="checkbox-line"><input type="checkbox" name="documented_authorization" required><span>I have written client authorization covering this exact scope and assessment period.</span></label><label class="checkbox-line"><input type="checkbox" name="allow_loopback"><span>Allow loopback addresses (for a local test fixture or lab only).</span></label><label class="checkbox-line"><input type="checkbox" name="allow_private_networks"><span>Allow private LAN addresses (use only with explicit written permission).</span></label></div><div class="risk-callout">The app records the authorization reference and the owner’s attestation. Keep the underlying authorization with your client records.</div><div class="live-controls" style="justify-content:flex-end;margin-top:15px"><button class="button ghost" type="button" id="cancel-target">Cancel</button><button class="button primary" type="submit">Save authorization</button></div><div id="target-error" class="auth-error"></div></form></div>`;document.body.append(modal);$("#cancel-target",modal).onclick=()=>modal.remove();$("#target-form",modal).onsubmit=async event=>{event.preventDefault();const form=new FormData(event.currentTarget);const values=Object.fromEntries(form);const local=new Date(values.expires_at);const payload={name:values.name,base_url:values.base_url,authorized_by:values.authorized_by,authorization_reference:values.authorization_reference,expires_at:local.toISOString(),documented_authorization:form.has("documented_authorization"),allow_loopback:form.has("allow_loopback"),allow_private_networks:form.has("allow_private_networks")};try{await api("/api/targets",{method:"POST",body:JSON.stringify(payload)});modal.remove();await loadAll();renderTargets();toast("Authorization record saved.","success");}catch(error){$("#target-error",modal).textContent=error.message;}};}

  function renderAgent(){const available=!!state.dashboard?.ai_available;$("#view").innerHTML=`${heading("BOUNDED BROWSER INTELLIGENCE","Agent configuration","AI is optional. Without provider credentials, deterministic passive scanning continues and no model reasoning is fabricated.")}<div class="content-grid"><section class="panel"><div class="panel-head"><h2>Provider status</h2><span class="badge ${available?"good":"warning"}">${available?"Configured":"AI unavailable"}</span></div><div class="summary-line"><span>Provider integration</span><strong>OpenAI-compatible Chat Completions</strong></div><div class="summary-line"><span>Endpoint</span><strong>${available?"Configured in server environment":"Not configured"}</strong></div><div class="summary-line"><span>Model</span><strong>${available?"Configured in server environment":"Not configured"}</strong></div><div class="summary-note">Set SENTINEL_AI_API_KEY and SENTINEL_AI_MODEL before starting the server. SENTINEL_AI_BASE_URL is optional and defaults to the OpenAI API endpoint. The key stays in the server environment; it is not stored in the browser or database.</div></section><section class="panel"><div class="panel-head"><h2>Action policy</h2><span class="badge good">Constrained</span></div><div class="summary-line"><span>Allowed proposals</span><strong>Inspect, scroll, screenshot, same-scope links</strong></div><div class="summary-line"><span>Credentials/forms</span><strong>Never submitted</strong></div><div class="summary-line"><span>Arbitrary code / HTTP</span><strong>Not available</strong></div><div class="summary-line"><span>Iteration bound</span><strong>Up to 20 actions</strong></div><p class="help-text">Page titles and link labels are treated as untrusted input. Proposals are schema validated and passed through a deterministic scope policy. The model cannot make a vulnerability finding by itself.</p></section></div>`;}

  function renderSettings(){const worker=state.dashboard?.worker||{};$("#view").innerHTML=`${heading("WORKSPACE CONTROLS","Settings","Local runtime configuration and operational boundaries.")}<div class="content-grid"><section class="panel"><div class="panel-head"><h2>Service</h2><span class="badge good">Loopback only</span></div><div class="summary-line"><span>Dashboard bind</span><strong>127.0.0.1</strong></div><div class="summary-line"><span>Worker mode</span><strong>${escapeHtml(worker.mode||"local")}</strong></div><div class="summary-line"><span>Workspace database</span><strong>SQLite · local disk</strong></div><div class="summary-line"><span>Browser channel</span><strong>${escapeHtml(worker.browser_channel||"chromium")}</strong></div><div class="summary-line"><span>Chromium sandbox</span><strong>Enabled</strong></div></section><section class="panel"><div class="panel-head"><h2>Assessment defaults</h2><span class="badge">Safe passive mode</span></div><div class="summary-line"><span>Visible browser</span><strong>Default</strong></div><div class="summary-line"><span>Maximum pages</span><strong>10</strong></div><div class="summary-line"><span>Navigation depth</span><strong>2</strong></div><div class="summary-line"><span>Active checks</span><strong>Disabled</strong></div><p class="help-text">Per-assessment limits are configured when starting a scan. Cross-organization SaaS tenancy, remote workers, authentication flows and active testing are not implemented.</p></section></div>`;}

  async function renderAudit(){let rows=[];try{rows=await api("/api/audit");}catch(error){toast(error.message,"error");}$("#view").innerHTML=`${heading("TRACEABLE OPERATIONS","Audit logs","Authentication, authorization, assessment and finding changes recorded by this local workspace.")}<section class="panel"><div class="panel-head"><h2>Recent audit events</h2><span class="subtle">${rows.length} events</span></div>${rows.length?`<div class="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>${rows.map(row=>`<tr><td class="mono">${escapeHtml(fmtDate(row.created_at))}</td><td>${escapeHtml(row.email||"System worker")}</td><td>${escapeHtml(row.action)}</td><td class="mono">${escapeHtml(JSON.stringify(row.details||{}))}</td></tr>`).join("")}</tbody></table></div>`:empty("No audit events recorded yet.")}</section>`;}

  function wireCommon(){ $$('[data-action="new"]').forEach(button=>button.onclick=()=>navigate("new"));$$('[data-action="targets"]').forEach(button=>button.onclick=()=>navigate("targets"));$$('[data-action="history"]').forEach(button=>button.onclick=()=>navigate("history"));$$('[data-action="reports"]').forEach(button=>button.onclick=()=>navigate("reports"));$$('[data-open-scan]').forEach(button=>button.onclick=async()=>{state.activeScan=button.dataset.openScan;await loadScanEvents(state.activeScan);navigate("live");}); }

  init();
})();
