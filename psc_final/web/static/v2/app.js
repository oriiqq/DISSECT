"use strict";

// ─── State ────────────────────────────────────────────────────────────────────
const S = {
  sessions:    [],
  filtered:    [],
  selected:    null,   // session_id string
  detail:      null,   // full session JSON
  detailLoading: false,
  filter:      { tier: "all", query: "", minScore: 0 },
  sortCol:     "score",
  sortAsc:     false,
  view:        "queue",       // "queue" | "summary" | "iocs" | "ti"
  detailTab:   "overview",    // "overview" | "threats" | "rules" | "code"
  filename:    null,
  uploadTs:    null,
  uploading:   false,
  stats:       { p1: 0, p2: 0, p3: 0, total: 0, campaigns: 0 },
  campaigns:   [],
  iocData:     null,
  tiData:      null,
  tiLoading:   false,
  density:     localStorage.getItem("dissect_density") || "normal",
  paneWidth:   parseInt(localStorage.getItem("dissect_pane_w") || "420", 10),
};

// ─── Tier helpers ─────────────────────────────────────────────────────────────
const TIER_CLS = { P1_INCIDENT: "p1", P2_ALERT: "p2", P3_WARNING: "p3", INFO: "info", CLEAN: "clean" };
const TIER_LBL = { P1_INCIDENT: "P1", P2_ALERT: "P2", P3_WARNING: "P3", INFO: "INFO", CLEAN: "CLEAN" };
function tc(tier) { return TIER_CLS[tier] || "clean"; }
function tl(tier) { return TIER_LBL[tier] || tier; }

// ─── Utils ────────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function fmtTime(iso) { if (!iso) return "—"; return new Date(iso).toISOString().slice(11, 19); }
function fmtDate(iso) { if (!iso) return "—"; return new Date(iso).toISOString().slice(0, 16).replace("T", " "); }
function fmtDur(s) {
  if (!s || s < 1) return "—";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
function copyText(text) {
  navigator.clipboard.writeText(text)
    .then(() => toast("Copied to clipboard", "success", 1500))
    .catch(() => toast("Copy failed — check browser permissions", "error"));
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function toast(msg, type = "info", duration = 2500) {
  let root = document.getElementById("toast-root");
  if (!root) {
    root = document.createElement("div");
    root.id = "toast-root";
    document.body.appendChild(root);
  }
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  root.appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 220);
  }, duration);
}

// ─── API ──────────────────────────────────────────────────────────────────────
const API = {
  async get(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${url}: ${r.status}`);
    return r.json();
  },
  sessions: () => API.get("/api/sessions"),
  session:  (id) => API.get(`/api/sessions/${encodeURIComponent(id)}`),
  iocs:     () => API.get("/api/iocs"),
  ti:       () => API.get("/api/ti"),
  async upload(file) {
    const fd = new FormData();
    fd.append("file", file, file.name);
    const r = await fetch("/api/upload", { method: "POST", body: fd });
    return r.json();
  },
};

// ─── Filter / sort ────────────────────────────────────────────────────────────
function applyFilter() {
  const { tier, query, minScore } = S.filter;
  const q = query.toLowerCase().trim();
  S.filtered = S.sessions.filter(s => {
    if (tier !== "all" && s.alert_tier !== tier) return false;
    if (s.weighted_score < minScore) return false;
    if (q) {
      const hay = `${s.host_id} ${s.process_id} ${s.technique_set.join(" ")}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const TIER_ORDER = { P1_INCIDENT: 4, P2_ALERT: 3, P3_WARNING: 2, INFO: 1, CLEAN: 0 };
  S.filtered.sort((a, b) => {
    let va, vb;
    if (S.sortCol === "score") { va = a.weighted_score; vb = b.weighted_score; }
    else if (S.sortCol === "host") { va = a.host_id; vb = b.host_id; }
    else if (S.sortCol === "time") { va = a.start_time || ""; vb = b.start_time || ""; }
    else if (S.sortCol === "tier") { va = TIER_ORDER[a.alert_tier] || 0; vb = TIER_ORDER[b.alert_tier] || 0; }
    else { va = a.weighted_score; vb = b.weighted_score; }
    return S.sortAsc ? (va > vb ? 1 : va < vb ? -1 : 0) : (va < vb ? 1 : va > vb ? -1 : 0);
  });
}

// ─── Icons (inline SVG strings) ───────────────────────────────────────────────
const ICON = {
  queue:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="3" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="3" cy="18" r="1" fill="currentColor" stroke="none"/></svg>`,
  summary:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="9" x2="9" y2="21"/></svg>`,
  iocs:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  ti:       `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  timeline: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  sigma:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/></svg>`,
  beacon:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49M7.76 16.24a6 6 0 0 1 0-8.49M20.07 4.93a10 10 0 0 1 0 14.14M3.93 19.07a10 10 0 0 1 0-14.14"/></svg>`,
  alert:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  lateral:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>`,
  logo:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
  file:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`,
  code:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
};

// ─── Render: Header ───────────────────────────────────────────────────────────
function renderHeader() {
  const { stats, filename, uploadTs, uploading } = S;
  const f = S.filter;
  return `
<header class="hdr">
  <div class="hdr-brand" title="DISSECT v2">
    <img class="hdr-logo-img" src="/static/icon.png" alt="DISSECT">
  </div>
  <span class="hdr-tagline">DISSECT</span>
  <div class="hdr-stats">
    ${stats.total ? `
      <button class="stat-pill p1 ${f.tier==="P1_INCIDENT"?"on":""}" onclick="setTierFilter('P1_INCIDENT')">
        <span class="dot"></span>${stats.p1} P1
      </button>
      <button class="stat-pill p2 ${f.tier==="P2_ALERT"?"on":""}" onclick="setTierFilter('P2_ALERT')">
        <span class="dot"></span>${stats.p2} P2
      </button>
      <button class="stat-pill p3 ${f.tier==="P3_WARNING"?"on":""}" onclick="setTierFilter('P3_WARNING')">
        <span class="dot"></span>${stats.p3} P3
      </button>
      <span class="hdr-total">${stats.total} sessions</span>
    ` : ""}
  </div>
  <span class="hdr-sep"></span>
  ${filename || uploadTs ? `
  <div class="hdr-meta">
    ${filename ? `<span class="hdr-file">${esc(filename)}</span>` : ""}
    ${uploadTs ? `<span class="hdr-ts">${esc(uploadTs)}</span>` : ""}
  </div>` : ""}
  <button class="shortcut-help-btn" onclick="showShortcutsModal()" title="Keyboard shortcuts (?)">?</button>
  <label class="upload-btn ${uploading ? "busy" : ""}">
    ${uploading ? `<span class="upload-spinner"></span> Analysing…` : `${ICON.logo} UPLOAD`}
    <input type="file" accept=".evtx,.json,.jsonl,.ndjson" onchange="doUpload(this)" style="display:none">
  </label>
</header>`;
}

// ─── Render: Sidebar ──────────────────────────────────────────────────────────
function renderSidebar() {
  const nav = [
    { id: "queue",   icon: ICON.queue,    tip: "Alert Queue  [g]" },
    { id: "summary", icon: ICON.summary,  tip: "Executive Summary  [s]" },
    { id: "iocs",    icon: ICON.iocs,     tip: "IOC Hub" },
    { id: "ti",      icon: ICON.ti,       tip: "Threat Intelligence" },
  ];
  const ext = [
    { href: "/timeline", icon: ICON.timeline, tip: "Attack Timeline" },
    { href: "/sigma",    icon: ICON.sigma,    tip: "Sigma Rules" },
  ];
  return `
<nav class="sidebar">
  ${nav.map(n => `
    <button class="nav-btn ${S.view===n.id?"active":""}" data-tip="${n.tip}" onclick="setView('${n.id}')">
      ${n.icon}
    </button>`).join("")}
  <div class="nav-sep"></div>
  ${ext.map(e => `
    <a class="nav-btn" href="${e.href}" data-tip="${e.tip}" target="_self">
      ${e.icon}
    </a>`).join("")}
</nav>`;
}

// ─── Render: Status bar ───────────────────────────────────────────────────────
function renderStatusBar() {
  const { view, filtered, sessions, filter, sortCol, sortAsc, selected } = S;
  const viewLabel = { queue: "Alert Queue", summary: "Summary", iocs: "IOC Hub", ti: "Threat Intel" }[view] || view;
  const filterParts = [];
  if (filter.tier !== "all") filterParts.push(filter.tier.replace("_INCIDENT", "").replace("_ALERT", "").replace("_WARNING", ""));
  if (filter.query) filterParts.push(`"${filter.query}"`);
  const selIdx = selected ? filtered.findIndex(s => s.session_id === selected) : -1;

  return `
<div class="status-bar">
  <span class="sb-item sb-view">${esc(viewLabel)}</span>
  <span class="sb-item">${filtered.length}${filtered.length !== sessions.length ? `/${sessions.length}` : ""} session${filtered.length !== 1 ? "s" : ""}</span>
  ${filterParts.length ? `<span class="sb-item" style="color:var(--amber)">filter: ${filterParts.join(" + ")}</span>` : ""}
  ${selected && selIdx >= 0 ? `<span class="sb-item">${selIdx + 1} of ${filtered.length}</span>` : ""}
  <span class="sb-item">sort: ${sortCol} ${sortAsc ? "↑" : "↓"}</span>
  <span class="sb-sep"></span>
  <span class="sb-hint">
    <span class="sb-kbd">j</span><span class="sb-kbd">k</span> nav &nbsp;·&nbsp;
    <span class="sb-kbd">/</span> search &nbsp;·&nbsp;
    <span class="sb-kbd">1</span>–<span class="sb-kbd">4</span> tabs &nbsp;·&nbsp;
    <span class="sb-kbd">?</span> help
  </span>
</div>`;
}

function updateStatusBar() {
  const sb = document.querySelector(".status-bar");
  if (sb) sb.outerHTML = renderStatusBar();
}

// ─── Render: Queue ────────────────────────────────────────────────────────────
function renderQueue() {
  return `
<div class="queue-layout fade-in">
  <div class="queue-pane" id="queue-pane" style="width:${S.paneWidth}px">
    ${renderFilterBar()}
    <div class="table-scroll" id="table-scroll">
      ${renderSessionTable()}
    </div>
  </div>
  <div class="drag-handle" id="drag-handle" title="Drag to resize pane"></div>
  <div class="detail-pane" id="detail-pane">
    ${S.detailLoading ? renderDetailSkeleton() : S.detail ? renderDetail() : renderDetailEmpty()}
  </div>
</div>`;
}

function renderFilterBar() {
  const { tier, query } = S.filter;
  return `
<div class="filter-bar">
  <div class="search-wrap">
    ${ICON.iocs.replace('viewBox', 'class="search-icon" viewBox')}
    <input class="search-input" id="search-input" type="text"
           placeholder="Search host, PID, technique…"
           value="${esc(query)}" oninput="onSearchInput(this.value)">
    ${query ? `<button class="search-clear" onclick="setQuery('')" title="Clear">✕</button>` : ""}
  </div>
  <div class="tier-pills">
    <button class="tier-pill all ${tier==="all"?"active":""}" onclick="setTierFilter('all')">ALL</button>
    <button class="tier-pill p1 ${tier==="P1_INCIDENT"?"active":""}" onclick="setTierFilter('P1_INCIDENT')">P1</button>
    <button class="tier-pill p2 ${tier==="P2_ALERT"?"active":""}" onclick="setTierFilter('P2_ALERT')">P2</button>
    <button class="tier-pill p3 ${tier==="P3_WARNING"?"active":""}" onclick="setTierFilter('P3_WARNING')">P3</button>
  </div>
  <span class="filter-count">${S.filtered.length}/${S.sessions.length}</span>
  <div class="density-toggle" title="Row density">
    <button class="density-btn ${S.density==="compact"?"active":""}" data-density="compact" onclick="setDensity('compact')" title="Compact">▪▪</button>
    <button class="density-btn ${S.density==="normal"?"active":""}" data-density="normal" onclick="setDensity('normal')" title="Normal">▬</button>
    <button class="density-btn ${S.density==="comfortable"?"active":""}" data-density="comfortable" onclick="setDensity('comfortable')" title="Comfortable">▭</button>
  </div>
</div>`;
}

function renderSessionTable() {
  if (!S.sessions.length) {
    return `<div class="queue-empty">
      ${ICON.file}
      <div class="queue-empty-title">No analysis loaded</div>
      <div class="queue-empty-sub">Upload a PowerShell EVTX or JSON log file to start triage</div>
      <label class="queue-upload-btn">
        ↑ Upload EVTX / JSON
        <input type="file" accept=".evtx,.json,.jsonl,.ndjson" onchange="doUpload(this)" style="display:none">
      </label>
    </div>`;
  }
  if (!S.filtered.length) {
    return `<div class="queue-empty">
      <div class="queue-empty-title">No matching sessions</div>
      <div class="queue-empty-sub">Adjust filters above to show results</div>
      <button class="queue-clear-btn" onclick="clearFilters()">Clear filters</button>
    </div>`;
  }
  const si = (col) => {
    if (S.sortCol !== col) return `<span class="sort-icon">⇅</span>`;
    return `<span class="sort-icon" style="color:var(--accent)">${S.sortAsc ? "↑" : "↓"}</span>`;
  };
  const densityCls = S.density !== "normal" ? ` ${S.density}` : "";
  const rows = S.filtered.map(s => {
    const cls = tc(s.alert_tier);
    const sel = s.session_id === S.selected;
    const techs = s.technique_set.slice(0, 3);
    const over  = s.technique_set.length - 3;
    const pct   = Math.round(s.weighted_score);
    return `
<tr class="srow ${cls} ${sel ? "selected" : ""}" onclick="selectSession('${esc(s.session_id)}')" data-id="${esc(s.session_id)}">
  <td class="col-sev"><span class="sev-dot ${cls}"></span></td>
  <td class="col-score">
    <div class="score-cell">
      <span class="score-num">${pct}</span>
      <div class="score-track"><div class="score-fill ${cls}" style="width:${pct}%"></div></div>
    </div>
  </td>
  <td class="col-host">
    <div class="host-cell">
      <span class="host-name">${esc(s.host_id)}</span>
      <span class="host-pid">PID ${s.process_id}</span>
    </div>
  </td>
  <td class="col-tech">
    <div class="tech-cell">
      ${techs.map(t => `<span class="tech-chip">${esc(t)}</span>`).join("")}
      ${over > 0 ? `<span class="tech-more">+${over}</span>` : ""}
    </div>
  </td>
  <td class="col-ioc"><span class="ioc-count">${s.ioc_count || "—"}</span></td>
  <td class="col-time"><span class="row-time">${fmtTime(s.start_time)}</span></td>
</tr>`;
  }).join("");
  return `
<table class="q-table${densityCls}">
  <thead>
    <tr>
      <th class="col-sev" onclick="sortBy('tier')">SEV${si("tier")}</th>
      <th class="col-score" onclick="sortBy('score')">SCORE${si("score")}</th>
      <th class="col-host" onclick="sortBy('host')">HOST${si("host")}</th>
      <th class="col-tech">TECHNIQUES</th>
      <th class="col-ioc" style="text-align:right">IOC</th>
      <th class="col-time" onclick="sortBy('time')">TIME${si("time")}</th>
    </tr>
  </thead>
  <tbody>${rows}</tbody>
</table>`;
}

// ─── Render: Detail skeleton ──────────────────────────────────────────────────
function renderDetailSkeleton() {
  return `
<div class="skeleton-wrap">
  <div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">
    <div class="sk-line" style="height:18px;width:36px;border-radius:3px"></div>
    <div class="sk-line" style="height:12px;width:55%;border-radius:3px"></div>
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap">
    <div class="sk-line" style="height:9px;width:80px"></div>
    <div class="sk-line" style="height:9px;width:60px"></div>
    <div class="sk-line" style="height:9px;width:70px"></div>
    <div class="sk-line" style="height:9px;width:55px"></div>
  </div>
  <div class="sk-line" style="height:1px;margin-top:14px;opacity:.3"></div>
  <div style="display:flex;gap:0;margin-top:6px">
    <div class="sk-line" style="height:34px;flex:1;border-radius:0"></div>
    <div class="sk-line" style="height:34px;flex:1;border-radius:0;opacity:.6;margin-left:1px"></div>
    <div class="sk-line" style="height:34px;flex:1;border-radius:0;opacity:.4;margin-left:1px"></div>
    <div class="sk-line" style="height:34px;flex:1;border-radius:0;opacity:.3;margin-left:1px"></div>
  </div>
  <div class="sk-line" style="height:9px;width:30%;margin-top:18px"></div>
  <div style="display:flex;gap:4px;margin-top:6px">
    ${[1,1,1,1,1,1].map((_,i) => `<div class="sk-line" style="height:42px;flex:1;opacity:${1-i*0.12}"></div>`).join("")}
  </div>
  <div class="sk-line" style="height:9px;width:40%;margin-top:16px"></div>
  <div class="sk-line" style="height:10px;width:90%;margin-top:6px"></div>
  <div class="sk-line" style="height:10px;width:75%"></div>
  <div class="sk-line" style="height:10px;width:85%"></div>
  <div class="sk-line" style="height:10px;width:60%"></div>
</div>`;
}

// ─── Render: Detail panel ─────────────────────────────────────────────────────
function renderDetailEmpty() {
  return `
<div class="detail-empty">
  ${ICON.queue}
  <div class="detail-empty-title">Select a session</div>
  <div class="detail-empty-sub">Click any row in the alert queue to load session detail, kill-chain analysis, and raw script blocks.</div>
  <div style="margin-top:12px;font-size:10.5px;color:var(--t3)">
    Press <span style="font-family:var(--mono);background:var(--bg3);padding:1px 5px;border-radius:2px;border:1px solid var(--bd)">j</span> /
    <span style="font-family:var(--mono);background:var(--bg3);padding:1px 5px;border-radius:2px;border:1px solid var(--bd)">k</span> to navigate rows
  </div>
</div>`;
}

function renderDetail() {
  const s = S.detail;
  if (!s) return renderDetailEmpty();
  const cls = tc(s.alert_tier);
  const threatCount = (s.has_beacon ? 1 : 0) + (s.ti_hits?.length || 0) + (s.lateral_moves?.length || 0);
  const rulesCount  = s.sigma_rules?.length || 0;
  const selIdx = S.filtered.findIndex(f => f.session_id === S.selected);
  return `
<div class="fade-in" style="display:flex;flex-direction:column;height:100%">
  <div class="detail-hdr">
    <div class="detail-title-row">
      <span class="tier-badge ${cls}">${tl(s.alert_tier)}</span>
      <span class="detail-session-id" title="${esc(s.session_id)}">${esc(s.session_id)}</span>
      <div class="detail-actions">
        <div class="nav-arrows">
          <button class="nav-arrow-btn" onclick="moveSelection(-1)" ${selIdx <= 0 ? "disabled" : ""} title="Previous session (k)">◀</button>
          <button class="nav-arrow-btn" onclick="moveSelection(1)" ${selIdx < 0 || selIdx >= S.filtered.length - 1 ? "disabled" : ""} title="Next session (j)">▶</button>
        </div>
        <a class="btn-sm" href="/sigma/download" title="Download all Sigma rules">Sigma ↓</a>
        <a class="btn-sm" href="/report/download" title="Full HTML report">Report ↓</a>
      </div>
    </div>
    <div class="detail-meta">
      <span class="meta-kv"><span class="meta-k">Host</span><span class="meta-v">${esc(s.host_id)}</span></span>
      <span class="meta-kv"><span class="meta-k">PID</span><span class="meta-v">${s.process_id}</span></span>
      <span class="meta-kv"><span class="meta-k">Score</span><span class="meta-v">${Math.round(s.weighted_score)}/100</span></span>
      <span class="meta-kv"><span class="meta-k">Blocks</span><span class="meta-v">${s.block_count}</span></span>
      <span class="meta-kv"><span class="meta-k">Tempo</span><span class="meta-v">${esc(s.tempo?.replace(/_/g, " "))}</span></span>
      ${s.duration_seconds > 1 ? `<span class="meta-kv"><span class="meta-k">Duration</span><span class="meta-v">${fmtDur(s.duration_seconds)}</span></span>` : ""}
      ${s.campaign_id ? `<span class="meta-kv"><span class="meta-k">Campaign</span><span class="meta-v" style="color:var(--purple)">${esc(s.campaign_id)}</span></span>` : ""}
      ${s.parent_process ? `<span class="meta-kv"><span class="meta-k">Parent</span><span class="meta-v">${esc(s.parent_process)}</span></span>` : ""}
    </div>
    ${s.beacon_profile?.is_beacon ? `
    <div class="beacon-alert">
      ${ICON.beacon}
      <span class="beacon-label">C2 Beacon Detected</span>
      <span class="beacon-meta">
        period ${s.beacon_profile.period_seconds}s &nbsp;·&nbsp;
        jitter ${Math.round(s.beacon_profile.jitter_pct * 100)}% &nbsp;·&nbsp;
        conf ${Math.round(s.beacon_profile.confidence * 100)}%
        ${s.beacon_profile.framework_hint ? ` &nbsp;·&nbsp; ${esc(s.beacon_profile.framework_hint.replace(/_/g, " ")).toUpperCase()}` : ""}
      </span>
    </div>` : ""}
  </div>

  <div class="detail-tabs" id="detail-tabs">
    <button class="dtab ${S.detailTab==="overview"?"active":""}" onclick="setDetailTab('overview')">OVERVIEW</button>
    <button class="dtab ${S.detailTab==="threats"?"active":""}" onclick="setDetailTab('threats')">
      THREATS${threatCount > 0 ? `<span class="dtab-badge">${threatCount}</span>` : ""}
    </button>
    <button class="dtab ${S.detailTab==="rules"?"active":""}" onclick="setDetailTab('rules')">
      RULES${rulesCount > 0 ? `<span class="dtab-badge blue">${rulesCount}</span>` : ""}
    </button>
    <button class="dtab ${S.detailTab==="code"?"active":""}" onclick="setDetailTab('code')">
      CODE<span class="dtab-badge teal">${s.block_count}</span>
    </button>
  </div>

  <div style="flex:1;overflow-y:auto">
    <div class="tab-pane ${S.detailTab==="overview"?"active":""}" id="tab-overview">
      ${renderTabOverview(s)}
    </div>
    <div class="tab-pane ${S.detailTab==="threats"?"active":""}" id="tab-threats">
      ${renderTabThreats(s)}
    </div>
    <div class="tab-pane ${S.detailTab==="rules"?"active":""}" id="tab-rules">
      ${renderTabRules(s)}
    </div>
    <div class="tab-pane ${S.detailTab==="code"?"active":""}" id="tab-code">
      ${renderTabCode(s)}
    </div>
  </div>
</div>`;
}

// ─── Kill-chain data ──────────────────────────────────────────────────────────
const KC_STAGES = [
  { name: "Execution",    cls: "blue",   color: "var(--blue)",   techs: ["EXEC_POLICY_BYPASS","IEX_EXEC","REFLECTIVE_INJECT","SHELLCODE_MARSHAL","PROC_HOLLOW","PROC_INJECT_OPENPROC","LOLBIN_CERTUTIL","LOLBIN_MSHTA","LOLBIN_REGSVR32","LOLBIN_RUNDLL32","LOLBIN_BITSADMIN"] },
  { name: "Def. Evasion", cls: "amber",  color: "var(--amber)",  techs: ["AMSI_BYPASS_REFLECT","AMSI_BYPASS_COM","AMSI_BYPASS_PATCH","AMSI_FORCE_DISABLE","ETW_BYPASS","ETW_PATCH_INLINE","ETW_PROVIDER_DISABLE","AV_EXCLUSION","CLM_BYPASS","ENCODED_CMD","HIGH_ENTROPY_BLOB"] },
  { name: "Persistence",  cls: "teal",   color: "var(--teal)",   techs: ["WMI_PERSIST","SCHTASK_CREATE","SCHTASK_HIJACK","REG_PERSIST"] },
  { name: "Cred. Access", cls: "p1",     color: "var(--red)",    techs: ["CRED_HARVEST","KERBEROAST_SPN","ASREPROAST","DPAPI_DECRYPT","SAM_DUMP","DCSYNC_PATTERN","LSASS_READ"] },
  { name: "Lateral",      cls: "purple", color: "var(--purple)", techs: ["WMIC_REMOTE_EXEC","LATERAL_PSREMOTING","LATERAL_INVOKE_CMD","LATERAL_WMI_EXEC","COM_LATERAL"] },
  { name: "C2",           cls: "p1",     color: "var(--red)",    techs: ["DOWNLOAD_CRADLE_WC","DOWNLOAD_CRADLE_BITS","DOWNLOAD_CRADLE_IWR","COBALT_STRIKE","REVERSE_SHELL"] },
];

function renderTabOverview(s) {
  const techs = new Set(s.technique_set || []);
  const kcBar = KC_STAGES.map(stage => {
    const hit = stage.techs.some(t => techs.has(t));
    return `
<div class="kc-stage ${hit ? "hit" : ""}" style="${hit ? `background:${stage.color}1a;border-color:${stage.color}55;` : ""}">
  <div class="kc-stage-name" style="${hit ? `color:${stage.color}` : ""}">${stage.name}</div>
  <div class="kc-dot">${hit ? `<span style="color:${stage.color}">●</span>` : `<span style="color:var(--bd3)">○</span>`}</div>
</div>`;
  }).join("");

  const techTags = [...techs].sort().map(t => `<span class="tech-tag-lg">${esc(t)}</span>`).join("");

  return `
<div class="sec-label">Kill-Chain Coverage</div>
<div class="kc-bar">${kcBar}</div>
${techs.size ? `
<div class="sec-label">Techniques Detected (${techs.size})</div>
<div class="tech-tags">${techTags}</div>
` : `<div style="color:var(--t3);font-size:12px">No techniques detected in this session.</div>`}`;
}

function renderTabThreats(s) {
  const parts = [];

  if (s.beacon_profile?.is_beacon) {
    const bp = s.beacon_profile;
    parts.push(`
<div class="threat-card amber">
  <div class="threat-card-title" style="color:var(--amber)">${ICON.beacon} C2 Beacon Pattern</div>
  <div class="threat-row" style="font-family:var(--mono);font-size:11px;color:var(--amber);opacity:.9">
    Period: ${bp.period_seconds}s &nbsp;·&nbsp; Jitter: ${Math.round(bp.jitter_pct * 100)}% &nbsp;·&nbsp;
    Confidence: ${Math.round(bp.confidence * 100)}% &nbsp;·&nbsp; Samples: ${bp.sample_count}
    ${bp.framework_hint ? ` &nbsp;·&nbsp; ${esc(bp.framework_hint.replace(/_/g, " ").toUpperCase())}` : ""}
  </div>
</div>`);
  }

  if (s.ti_hits?.length) {
    const rows = s.ti_hits.map(h => {
      const srcCls = h.source === "threatfox" ? "tf" : h.source === "urlhaus" ? "uh" : "mb";
      const confCls = h.confidence >= 80 ? "hi" : h.confidence >= 50 ? "mid" : "";
      return `
<div class="threat-row">
  <span class="src-badge ${srcCls}">${esc(h.source)}</span>
  <span class="ioc-val" title="${esc(h.ioc_value)}">${esc(h.ioc_value.slice(0, 60))}${h.ioc_value.length > 60 ? "…" : ""}</span>
  ${h.malware_name ? `<span style="color:var(--t2);font-size:11px;flex-shrink:0">→ ${esc(h.malware_name)}</span>` : ""}
  <span class="conf-pct ${confCls}">${h.confidence}%</span>
</div>`;
    }).join("");
    parts.push(`
<div class="threat-card red">
  <div class="threat-card-title" style="color:var(--red)">${ICON.alert} Threat Intelligence Matches (${s.ti_hits.length})</div>
  ${rows}
</div>`);
  }

  if (s.lateral_moves?.length) {
    const rows = s.lateral_moves.map(m => `
<div class="threat-row">
  <span class="ioc-val" style="font-family:var(--mono)">${esc(m.source_host)}</span>
  <span style="color:var(--red);flex-shrink:0">${ICON.lateral}</span>
  <span class="ioc-val" style="font-family:var(--mono)">${esc(m.target_host)}</span>
  <span class="src-badge tf" style="flex-shrink:0">${esc(m.evidence)}</span>
  <span style="color:var(--t3);font-size:10px;font-family:var(--mono);flex-shrink:0">${esc(m.mitre_id)}</span>
</div>`).join("");
    parts.push(`
<div class="threat-card purple">
  <div class="threat-card-title" style="color:var(--purple)">${ICON.lateral} Lateral Movement (${s.lateral_moves.length} hop${s.lateral_moves.length !== 1 ? "s" : ""})</div>
  ${rows}
</div>`);
  }

  if (s.iocs?.length) {
    const shown = s.iocs.slice(0, 24);
    const more  = s.iocs.length - shown.length;
    parts.push(`
<div class="sec-label">Extracted IOCs (${s.iocs.length})</div>
<div class="ioc-chip-wrap">
  ${shown.map(v => `<span class="ioc-chip" title="${esc(v)}" onclick="copyText('${esc(v)}')" style="cursor:pointer">${esc(v)}</span>`).join("")}
  ${more > 0 ? `<span style="color:var(--t3);font-size:11px;align-self:center">+${more} more</span>` : ""}
</div>`);
  }

  if (!parts.length) {
    return `<div style="color:var(--t3);font-size:12px;padding-top:4px">No threat signals detected for this session.</div>`;
  }
  return parts.join("");
}

function renderTabRules(s) {
  if (!s.sigma_rules?.length) {
    return `<div style="color:var(--t3);font-size:12px">No Sigma rules generated — no findings above threshold.</div>`;
  }
  return s.sigma_rules.map((r, i) => {
    const lvlCls = r.level || "low";
    return `
<div class="sigma-card">
  <div class="sigma-card-head">
    <span class="level-badge ${lvlCls}">${esc(r.level)}</span>
    <span class="sigma-title" title="${esc(r.title)}">${esc(r.title)}</span>
    <button class="sigma-toggle-btn" onclick="toggleSigma('sigma-yaml-${i}', this)">View YAML</button>
  </div>
  <div class="sigma-meta">
    ID: <code>${esc(r.rule_id?.slice(0, 8))}…</code>
    &nbsp;·&nbsp; MITRE: <code>${esc(r.mitre_id)}</code>
    &nbsp;·&nbsp; ${(r.tags || []).join(", ")}
  </div>
  <div class="sigma-yaml" id="sigma-yaml-${i}" style="display:none">
    <button class="copy-btn" id="copy-btn-${i}" onclick="copySigma(${i})">Copy</button>${esc(r.yaml)}</div>
</div>`;
  }).join("");
}

function renderTabCode(s) {
  const parts = [];
  if (s.process_tree?.length) {
    const rows = s.process_tree.map(pe => `
<div class="proc-row">
  <span class="proc-ts">${pe.timestamp ? pe.timestamp.slice(11, 19) : "—"}</span>
  <span class="proc-eid">${pe.event_id}</span>
  ${pe.parent_name ? `<span class="proc-parent">${esc(pe.parent_name.slice(0, 18))}</span><span class="proc-arrow"> → </span>` : ""}
  <span class="proc-name">${esc(pe.process_name.slice(0, 24))}</span>
  ${pe.command_line ? `<span class="proc-cmd">&nbsp;${esc(pe.command_line.slice(0, 90))}${pe.command_line.length > 90 ? "…" : ""}</span>` : ""}
</div>`).join("");
    parts.push(`
<div class="sec-label">Process Tree (${s.process_tree.length})</div>
<div class="proc-tree">${rows}</div>`);
  }

  parts.push(`<div class="sec-label" style="margin-top:${s.process_tree?.length ? "14px" : "0"}">Script Blocks (${s.block_count})</div>`);
  (s.blocks || []).forEach((b, i) => {
    const sevCls = b.severity >= 80 ? "c" : b.severity >= 60 ? "h" : b.severity >= 40 ? "m" : "l";
    const findings = (b.findings || []).map(f => `<span class="blk-find">${esc(f.technique_id)}</span>`).join("");
    parts.push(`
<div class="block-card">
  <div class="block-head">
    <span class="sev-chip ${sevCls}">sev ${b.severity}</span>
    ${b.timestamp ? `<span class="blk-ts">${b.timestamp.slice(11, 19)}</span>` : ""}
    <span class="blk-entropy">H=${b.entropy}</span>
    ${b.path ? `<span class="blk-path" title="${esc(b.path)}">${esc(b.path.slice(-48))}</span>` : ""}
  </div>
  ${findings ? `<div class="blk-findings">${findings}</div>` : ""}
  <div class="code-pre">${esc(b.decoded_text)}${b.decoded_text?.length >= 1200 ? "\n…" : ""}</div>
  ${b.raw_text ? `
  <details>
    <summary class="raw-toggle">Raw (pre-deobfuscation)</summary>
    <div class="code-pre" style="border-top:1px solid var(--bd);max-height:80px">${esc(b.raw_text)}</div>
  </details>` : ""}
</div>`);
  });
  return parts.join("");
}

// ─── Render: Summary view ──────────────────────────────────────────────────────
function renderSummary() {
  if (!S.sessions.length) {
    return `<div class="view-wrap fade-in">
      <div class="queue-empty" style="min-height:60vh">
        ${ICON.summary}
        <div class="queue-empty-title">No data loaded</div>
        <div class="queue-empty-sub">Upload a log file from the Alert Queue to see the executive summary.</div>
      </div>
    </div>`;
  }
  const st = S.stats;
  const allTechs = new Set(S.sessions.flatMap(s => s.technique_set));
  const allIOCs  = S.sessions.reduce((n, s) => n + s.ioc_count, 0);
  const hosts    = new Set(S.sessions.map(s => s.host_id)).size;

  let riskCls = "low", riskLbl = "LOW";
  if (st.p1 > 0) { riskCls = "critical"; riskLbl = "CRITICAL"; }
  else if (st.p2 > 0) { riskCls = "high"; riskLbl = "HIGH"; }
  else if (st.p3 > 0) { riskCls = "medium"; riskLbl = "MEDIUM"; }

  const riskDesc = {
    critical: `Active incident indicators detected. ${st.p1} P1 session${st.p1 !== 1 ? "s" : ""} contain confirmed attack TTPs across ${hosts} host${hosts !== 1 ? "s" : ""}. Immediate response required.`,
    high:     `Alert-level activity detected. ${st.p2} P2 session${st.p2 !== 1 ? "s" : ""} require analyst review.`,
    medium:   `Warning-level activity detected. ${st.p3} P3 session${st.p3 !== 1 ? "s" : ""} scored above detection threshold.`,
    low:      `No significant threats detected. All ${st.total} sessions scored below alert threshold.`,
  }[riskCls];

  const techFreq = {};
  S.sessions.forEach(s => s.technique_set.forEach(t => { techFreq[t] = (techFreq[t] || 0) + 1; }));
  const topTechs = Object.entries(techFreq).sort((a,b) => b[1]-a[1]).slice(0, 20);

  const kcGrid = KC_STAGES.map(stage => {
    const hits = S.sessions.reduce((n, s) =>
      n + stage.techs.filter(t => s.technique_set.includes(t)).length, 0);
    return `
<div class="kc-cell ${hits ? "hit" : ""}" style="${hits ? `background:${stage.color}14;border-color:${stage.color}50;` : ""}">
  <div class="kc-cell-name" style="${hits ? `color:${stage.color}` : "color:var(--t3)"}">${stage.name}</div>
  <div class="kc-cell-count" style="${hits ? `color:${stage.color}` : "color:var(--bd3)"}">${hits || "—"}</div>
  ${hits ? `<div class="kc-cell-sub" style="color:${stage.color}">hit${hits !== 1 ? "s" : ""}</div>` : ""}
</div>`;
  }).join("");

  const topRows = [...S.sessions].sort((a,b) => b.weighted_score - a.weighted_score).slice(0, 5).map(s => {
    const cls = tc(s.alert_tier);
    return `
<tr onclick="setView('queue');setTimeout(()=>selectSession('${esc(s.session_id)}'),100)">
  <td><span class="tier-badge ${cls}">${tl(s.alert_tier)}</span></td>
  <td style="font-family:var(--mono);font-weight:600;color:${s.weighted_score >= 80 ? "var(--red)" : s.weighted_score >= 60 ? "var(--amber)" : "var(--teal)"}">${Math.round(s.weighted_score)}</td>
  <td style="font-family:var(--mono);font-size:11px">${esc(s.host_id)}</td>
  <td>${s.technique_set.slice(0, 3).map(t => `<span class="tech-chip">${esc(t)}</span>`).join("")}</td>
  <td style="color:var(--t3)">${s.ioc_count}</td>
  <td style="color:var(--t3);font-family:var(--mono);font-size:11px">${fmtTime(s.start_time)}</td>
</tr>`;
  }).join("");

  return `<div class="view-wrap fade-in">
<div class="risk-banner ${riskCls}">
  <div>
    <div style="font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;opacity:.7;margin-bottom:4px">Overall Risk</div>
    <div class="risk-level">${riskLbl}</div>
  </div>
  <div class="risk-desc">${riskDesc}</div>
  ${S.filename ? `<div class="risk-meta">${esc(S.filename)}<br>${esc(S.uploadTs || "")}</div>` : ""}
</div>

<div class="stat-grid">
  <div class="stat-tile p1"><div class="stat-tile-val">${st.p1}</div><div class="stat-tile-label">P1 Incidents</div></div>
  <div class="stat-tile p2"><div class="stat-tile-val">${st.p2}</div><div class="stat-tile-label">P2 Alerts</div></div>
  <div class="stat-tile p3"><div class="stat-tile-val">${st.p3}</div><div class="stat-tile-label">P3 Warnings</div></div>
  <div class="stat-tile"><div class="stat-tile-val">${st.total}</div><div class="stat-tile-label">Sessions</div></div>
  <div class="stat-tile"><div class="stat-tile-val">${allTechs.size}</div><div class="stat-tile-label">TTPs</div></div>
  <div class="stat-tile"><div class="stat-tile-val">${allIOCs}</div><div class="stat-tile-label">IOCs</div></div>
</div>

<div class="section-card">
  <div class="section-card-head">Kill-Chain Coverage</div>
  <div style="padding:12px 14px"><div class="kc-grid">${kcGrid}</div></div>
</div>

<div class="section-card">
  <div class="section-card-head">Top Threats <span style="margin-left:auto;font-weight:400;text-transform:none;letter-spacing:0;font-size:10.5px"><a href="/" style="color:var(--accent)">← Back to v1</a> &nbsp; <a href="/summary" style="color:var(--accent)">Full summary →</a></span></div>
  <table class="top-threats-table">
    <thead><tr><th>TIER</th><th>SCORE</th><th>HOST</th><th>TECHNIQUES</th><th>IOCs</th><th>TIME</th></tr></thead>
    <tbody>${topRows}</tbody>
  </table>
</div>

${topTechs.length ? `
<div class="section-card">
  <div class="section-card-head">ATT&amp;CK Techniques Observed</div>
  <div style="padding:12px 14px">
    <div class="mitre-cloud">
      ${topTechs.map(([t,c]) => `<span class="mitre-chip">${esc(t)}<span class="mitre-cnt">${c}</span></span>`).join("")}
    </div>
  </div>
</div>` : ""}
</div>`;
}

// ─── Render: IOC view ──────────────────────────────────────────────────────────
function renderIOCs() {
  if (!S.iocData) {
    if (!S.sessions.length) {
      return `<div class="view-wrap fade-in"><div class="queue-empty" style="min-height:60vh">${ICON.iocs}<div class="queue-empty-title">No data</div></div></div>`;
    }
    S.iocData = null;
    loadIOCs();
    return `<div class="view-wrap fade-in"><div class="loading-state"><div class="boot-ring"></div><div class="loading-text">Loading IOC Hub…</div></div></div>`;
  }
  const d = S.iocData;
  if (!d.total) {
    return `<div class="view-wrap fade-in"><div class="queue-empty" style="min-height:60vh">${ICON.iocs}<div class="queue-empty-title">No IOCs extracted</div></div></div>`;
  }
  const types = [
    ["all", `All (${d.total})`],
    ["url",  `URLs (${d.counts?.url || 0})`],
    ["ip",   `IPs (${d.counts?.ip || 0})`],
    ["hash", `Hashes (${d.counts?.hash || 0})`],
    ["path", `Paths (${d.counts?.path || 0})`],
  ];
  return `<div class="view-wrap fade-in">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
  <div class="ioc-type-tabs">
    ${types.map(([k,l]) => `<button class="ioc-tab ${k==="all"?"active":""}" data-type="${k}" onclick="iocFilter(this,'${k}')">${l}</button>`).join("")}
  </div>
  <div class="search-wrap" style="max-width:260px">
    ${ICON.iocs.replace('viewBox','class="search-icon" viewBox')}
    <input class="search-input" id="ioc-search" type="text" placeholder="Search indicators…"
           oninput="iocSearch(this.value)" style="background:var(--bg2)">
  </div>
  <span id="ioc-count" style="font-size:10.5px;color:var(--t3);margin-left:auto"></span>
  <a href="/iocs/download/csv" class="btn-sm">CSV ↓</a>
  <a href="/iocs/download/txt" class="btn-sm">TXT ↓</a>
</div>
<div class="section-card">
  <table class="data-table">
    <thead><tr><th style="width:60px">TYPE</th><th>INDICATOR</th><th style="width:50px">HITS</th><th style="width:70px">SESSIONS</th><th style="width:56px"></th></tr></thead>
    <tbody id="ioc-tbody">
      ${d.entries.map(e => `
<tr class="ioc-row" data-type="${esc(e.ioc_type)}" data-val="${esc(e.value.toLowerCase())}">
  <td><span class="type-badge ${esc(e.ioc_type)}">${esc(e.ioc_type)}</span></td>
  <td class="mono-val" title="${esc(e.value)}">${esc(e.value)}</td>
  <td style="font-family:var(--mono);font-weight:600">${e.count}</td>
  <td style="color:var(--t3)">${e.session_count}</td>
  <td><button class="action-btn" onclick="copyText('${esc(e.value)}')">Copy</button></td>
</tr>`).join("")}
    </tbody>
  </table>
</div></div>`;
}

// ─── Render: TI view ──────────────────────────────────────────────────────────
function renderTI() {
  if (S.tiLoading) {
    return `<div class="view-wrap fade-in"><div class="loading-state"><div class="boot-ring"></div><div class="loading-text">Querying ThreatFox, URLhaus, MalwareBazaar…</div></div></div>`;
  }
  if (!S.tiData) {
    if (!S.sessions.length) {
      return `<div class="view-wrap fade-in"><div class="queue-empty" style="min-height:60vh">${ICON.ti}<div class="queue-empty-title">No data</div></div></div>`;
    }
    loadTI();
    return `<div class="view-wrap fade-in"><div class="loading-state"><div class="boot-ring"></div><div class="loading-text">Querying threat feeds…</div></div></div>`;
  }
  const d = S.tiData;
  if (!d.total) {
    return `<div class="view-wrap fade-in"><div class="queue-empty" style="min-height:60vh">${ICON.ti}<div class="queue-empty-title">No TI matches</div><div class="queue-empty-sub">No IOCs matched ThreatFox, URLhaus, or MalwareBazaar.</div></div></div>`;
  }
  const sources = [...new Set(d.hits.map(h => h.source))];
  return `<div class="view-wrap fade-in">
<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">
  <div class="ti-src-tabs">
    <button class="ioc-tab active" data-src="all" onclick="tiFilter(this,'all')">All (${d.total})</button>
    ${sources.map(src => `<button class="ioc-tab" data-src="${esc(src)}" onclick="tiFilter(this,'${esc(src)}')">${esc(src)} (${d.hit_counts?.[src]||0})</button>`).join("")}
  </div>
</div>
<div class="section-card">
  <table class="data-table">
    <thead><tr><th style="width:80px">SOURCE</th><th style="width:60px">TYPE</th><th>INDICATOR</th><th style="width:140px">MALWARE</th><th style="width:55px">CONF.</th><th style="width:100px">FIRST SEEN</th><th style="width:56px"></th></tr></thead>
    <tbody id="ti-tbody">
      ${d.hits.map(h => {
        const srcCls = h.source==="threatfox"?"tf":h.source==="urlhaus"?"uh":"mb";
        const confCls = h.confidence>=80?"hi":h.confidence>=50?"mid":"";
        return `
<tr class="ti-row" data-src="${esc(h.source)}">
  <td><span class="src-badge ${srcCls}">${esc(h.source)}</span></td>
  <td><span class="type-badge ${esc(h.ioc_type)}">${esc(h.ioc_type)}</span></td>
  <td class="mono-val" title="${esc(h.ioc_value)}">${esc(h.ioc_value)}</td>
  <td style="font-size:12px;font-weight:500">${h.malware_name ? esc(h.malware_name) : "—"}<br>
    ${h.threat_type ? `<span style="font-size:10px;color:var(--t3)">${esc(h.threat_type)}</span>` : ""}</td>
  <td><span class="conf-pct ${confCls}">${h.confidence}%</span></td>
  <td style="font-size:11px;color:var(--t3)">${h.first_seen ? h.first_seen.slice(0,10) : "—"}</td>
  <td><button class="action-btn" onclick="copyText('${esc(h.ioc_value)}')">Copy</button></td>
</tr>`;}).join("")}
    </tbody>
  </table>
</div></div>`;
}

// ─── Full render ──────────────────────────────────────────────────────────────
function render() {
  const mainContent = S.view === "queue"   ? renderQueue()
    : S.view === "summary" ? renderSummary()
    : S.view === "iocs"    ? renderIOCs()
    : S.view === "ti"      ? renderTI()
    : renderQueue();

  document.getElementById("app").innerHTML = `
${renderHeader()}
<div class="app-body">
  ${renderSidebar()}
  <div class="main" id="main">
    ${mainContent}
  </div>
</div>
${renderStatusBar()}`;

  initDrag();
}

// Partial updates — avoid full re-renders when possible
function patchHeader() {
  const hdr = document.querySelector(".hdr");
  if (hdr) hdr.outerHTML = renderHeader();
}

function patchTable() {
  applyFilter();
  const scroll = document.getElementById("table-scroll");
  if (scroll) scroll.innerHTML = renderSessionTable();
  const fb = document.querySelector(".filter-bar");
  if (fb) {
    const cnt = fb.querySelector(".filter-count");
    if (cnt) cnt.textContent = `${S.filtered.length}/${S.sessions.length}`;
  }
  updateStatusBar();
}

function patchDetail() {
  const dp = document.getElementById("detail-pane");
  if (!dp) return;
  if (S.detailLoading) {
    dp.innerHTML = renderDetailSkeleton();
  } else {
    dp.innerHTML = S.detail ? renderDetail() : renderDetailEmpty();
  }
  updateStatusBar();
}

// ─── Event handlers ───────────────────────────────────────────────────────────
async function selectSession(id) {
  if (S.selected === id) return;
  S.selected = id;
  S.detailTab = "overview";
  S.detailLoading = true;
  patchDetail();
  // highlight row immediately and scroll into view
  document.querySelectorAll(".srow").forEach(r => {
    r.classList.toggle("selected", r.dataset.id === id);
  });
  const selRow = document.querySelector(`.srow[data-id="${CSS.escape(id)}"]`);
  if (selRow) selRow.scrollIntoView({ block: "nearest" });
  try {
    S.detail = await API.session(id);
  } catch (e) {
    S.detail = null;
    toast("Failed to load session detail", "error");
    console.error(e);
  }
  S.detailLoading = false;
  patchDetail();
}

function setView(view) {
  if (S.view === view) return;
  S.view = view;
  if (view === "iocs" && !S.iocData && S.sessions.length) loadIOCs();
  if (view === "ti"   && !S.tiData  && S.sessions.length) loadTI();
  render();
}

function setTierFilter(tier) {
  S.filter.tier = S.filter.tier === tier && tier !== "all" ? "all" : tier;
  if (S.view !== "queue") { S.view = "queue"; render(); return; }
  applyFilter();
  document.querySelectorAll(".stat-pill").forEach(b => {
    const isTier = b.classList.contains("p1") && tier === "P1_INCIDENT" ||
                   b.classList.contains("p2") && tier === "P2_ALERT"    ||
                   b.classList.contains("p3") && tier === "P3_WARNING";
    if (isTier) b.classList.toggle("on");
  });
  document.querySelectorAll(".tier-pill").forEach(b => {
    b.classList.toggle("active",
      (b.classList.contains("all") && S.filter.tier === "all") ||
      (b.classList.contains("p1")  && S.filter.tier === "P1_INCIDENT") ||
      (b.classList.contains("p2")  && S.filter.tier === "P2_ALERT")    ||
      (b.classList.contains("p3")  && S.filter.tier === "P3_WARNING")
    );
  });
  patchTable();
}

let _searchTimer;
function onSearchInput(val) {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(() => setQuery(val), 120);
}

function setQuery(val) {
  S.filter.query = val;
  const inp = document.getElementById("search-input");
  if (inp && inp !== document.activeElement) inp.value = val;
  const fb = document.querySelector(".filter-bar");
  if (fb) {
    let clr = fb.querySelector(".search-clear");
    if (val && !clr) {
      const wrap = fb.querySelector(".search-wrap");
      if (wrap) { const b = document.createElement("button"); b.className = "search-clear"; b.textContent = "✕"; b.onclick = () => setQuery(""); wrap.appendChild(b); }
    } else if (!val && clr) { clr.remove(); }
  }
  applyFilter();
  patchTable();
}

function clearFilters() {
  S.filter = { tier: "all", query: "", minScore: 0 };
  applyFilter();
  patchTable();
}

function sortBy(col) {
  if (S.sortCol === col) S.sortAsc = !S.sortAsc;
  else { S.sortCol = col; S.sortAsc = col === "host"; }
  applyFilter();
  patchTable();
}

function setDetailTab(tab) {
  if (!S.detail) return;
  S.detailTab = tab;
  document.querySelectorAll(".dtab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  const btn = document.querySelector(`.dtab[onclick*="'${tab}'"]`);
  if (btn) btn.classList.add("active");
  const pane = document.getElementById(`tab-${tab}`);
  if (pane) pane.classList.add("active");
}

// ─── Enterprise: keyboard navigation ─────────────────────────────────────────
function moveSelection(dir) {
  if (!S.filtered.length) return;
  const idx = S.filtered.findIndex(s => s.session_id === S.selected);
  let next;
  if (idx < 0) {
    next = dir > 0 ? 0 : S.filtered.length - 1;
  } else {
    next = Math.max(0, Math.min(S.filtered.length - 1, idx + dir));
    if (next === idx) return;
  }
  selectSession(S.filtered[next].session_id);
}

function handleKeyDown(e) {
  const tag = (e.target.tagName || "").toLowerCase();
  const isInput = tag === "input" || tag === "textarea" || e.target.isContentEditable;

  if (e.key === "Escape") {
    const modal = document.querySelector(".modal-overlay");
    if (modal) { modal.remove(); return; }
    if (S.selected) {
      S.selected = null;
      S.detail = null;
      patchDetail();
      document.querySelectorAll(".srow").forEach(r => r.classList.remove("selected"));
    }
    return;
  }

  if (e.key === "?" && !isInput) { e.preventDefault(); showShortcutsModal(); return; }
  if (isInput) return;

  if (e.key === "j") { e.preventDefault(); if (S.view === "queue") moveSelection(1); return; }
  if (e.key === "k") { e.preventDefault(); if (S.view === "queue") moveSelection(-1); return; }
  if (e.key === "/") { e.preventDefault(); const inp = document.getElementById("search-input"); if (inp) { inp.focus(); inp.select(); } return; }
  if (e.key === "1") { setDetailTab("overview"); return; }
  if (e.key === "2") { setDetailTab("threats"); return; }
  if (e.key === "3") { setDetailTab("rules"); return; }
  if (e.key === "4") { setDetailTab("code"); return; }
  if (e.key === "g") { setView("queue"); return; }
  if (e.key === "s") { setView("summary"); return; }
}

// ─── Enterprise: shortcuts modal ──────────────────────────────────────────────
function showShortcutsModal() {
  const existing = document.querySelector(".modal-overlay");
  if (existing) { existing.remove(); return; }
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  overlay.innerHTML = `
<div class="shortcuts-modal" onclick="event.stopPropagation()">
  <h2>Keyboard Shortcuts</h2>
  <div class="shortcut-group">
    <div class="shortcut-group-label">Navigation</div>
    <div class="shortcut-row"><span>Next session</span><span class="shortcut-keys"><span class="kbd">j</span></span></div>
    <div class="shortcut-row"><span>Previous session</span><span class="shortcut-keys"><span class="kbd">k</span></span></div>
    <div class="shortcut-row"><span>Focus search</span><span class="shortcut-keys"><span class="kbd">/</span></span></div>
    <div class="shortcut-row"><span>Deselect / close</span><span class="shortcut-keys"><span class="kbd">Esc</span></span></div>
  </div>
  <div class="shortcut-group">
    <div class="shortcut-group-label">Detail Tabs</div>
    <div class="shortcut-row"><span>Overview</span><span class="shortcut-keys"><span class="kbd">1</span></span></div>
    <div class="shortcut-row"><span>Threats</span><span class="shortcut-keys"><span class="kbd">2</span></span></div>
    <div class="shortcut-row"><span>Rules</span><span class="shortcut-keys"><span class="kbd">3</span></span></div>
    <div class="shortcut-row"><span>Code / Script Blocks</span><span class="shortcut-keys"><span class="kbd">4</span></span></div>
  </div>
  <div class="shortcut-group">
    <div class="shortcut-group-label">Views</div>
    <div class="shortcut-row"><span>Alert Queue</span><span class="shortcut-keys"><span class="kbd">g</span></span></div>
    <div class="shortcut-row"><span>Executive Summary</span><span class="shortcut-keys"><span class="kbd">s</span></span></div>
    <div class="shortcut-row"><span>Toggle this help</span><span class="shortcut-keys"><span class="kbd">?</span></span></div>
  </div>
  <div class="modal-close-hint">Press <span class="kbd">Esc</span> or click outside to close</div>
</div>`;
  document.body.appendChild(overlay);
}

// ─── Enterprise: density toggle ───────────────────────────────────────────────
function setDensity(d) {
  S.density = d;
  localStorage.setItem("dissect_density", d);
  const tbl = document.querySelector(".q-table");
  if (tbl) {
    tbl.classList.remove("compact", "comfortable");
    if (d !== "normal") tbl.classList.add(d);
  }
  document.querySelectorAll(".density-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.density === d);
  });
}

// ─── Enterprise: resizable pane ───────────────────────────────────────────────
function initDrag() {
  const handle = document.getElementById("drag-handle");
  const qp = document.getElementById("queue-pane");
  if (!handle || !qp || handle._bound) return;
  handle._bound = true;

  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    handle.classList.add("dragging");
    const startX = e.clientX;
    const startW = qp.offsetWidth;

    const onMove = (mv) => {
      const newW = Math.max(260, Math.min(700, startW + mv.clientX - startX));
      qp.style.width = newW + "px";
      S.paneWidth = newW;
    };
    const onUp = () => {
      handle.classList.remove("dragging");
      localStorage.setItem("dissect_pane_w", S.paneWidth);
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

// Upload
async function doUpload(input) {
  const file = input?.files?.[0];
  if (!file) return;
  S.uploading = true;
  S.detail = null;
  S.selected = null;
  patchHeader();
  try {
    const data = await API.upload(file);
    if (data.error) {
      toast(`Upload failed: ${data.error}`, "error");
      return;
    }
    S.sessions  = data.sessions || [];
    S.campaigns = data.campaigns || [];
    S.filename  = data.filename;
    S.uploadTs  = data.upload_ts;
    S.stats     = data.stats || { p1: 0, p2: 0, p3: 0, total: S.sessions.length };
    S.filter    = { tier: "all", query: "", minScore: 0 };
    S.iocData   = null;
    S.tiData    = null;
    S.view      = "queue";
    applyFilter();
    render();
    toast(`Loaded ${S.sessions.length} session${S.sessions.length !== 1 ? "s" : ""} from ${data.filename || file.name}`, "success");
  } catch (e) {
    toast(`Upload error: ${e.message}`, "error");
  } finally {
    S.uploading = false;
    patchHeader();
  }
}

// IOC & TI loaders
async function loadIOCs() {
  try { S.iocData = await API.iocs(); render(); } catch (e) { console.error(e); }
}
async function loadTI() {
  S.tiLoading = true;
  render();
  try { S.tiData = await API.ti(); } catch (e) { console.error(e); }
  S.tiLoading = false;
  render();
}

// IOC view filter
function iocFilter(btn, type) {
  document.querySelectorAll(".ioc-tab").forEach(b => b.classList.toggle("active", b === btn));
  let shown = 0, total = 0;
  document.querySelectorAll(".ioc-row").forEach(row => {
    total++;
    const vis = type === "all" || row.dataset.type === type;
    row.style.display = vis ? "" : "none";
    if (vis) shown++;
  });
  const cnt = document.getElementById("ioc-count");
  if (cnt) cnt.textContent = shown < total ? `${shown} of ${total}` : "";
}
function iocSearch(q) {
  const lq = q.toLowerCase();
  document.querySelectorAll(".ioc-row").forEach(row => {
    row.style.display = !lq || row.dataset.val.includes(lq) ? "" : "none";
  });
}
function tiFilter(btn, src) {
  document.querySelectorAll(".ioc-tab").forEach(b => b.classList.toggle("active", b === btn));
  document.querySelectorAll(".ti-row").forEach(r => {
    r.style.display = src === "all" || r.dataset.src === src ? "" : "none";
  });
}

// Sigma YAML toggle
function toggleSigma(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  const open = el.style.display !== "none";
  el.style.display = open ? "none" : "block";
  btn.textContent = open ? "View YAML" : "Hide YAML";
}
function copySigma(i) {
  const el = document.getElementById(`sigma-yaml-${i}`);
  if (!el) return;
  copyText(el.textContent.replace(/^Copy/, "").trim());
  const btn = document.getElementById(`copy-btn-${i}`);
  if (btn) { btn.textContent = "Copied!"; btn.classList.add("copied"); setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 2000); }
}

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  document.addEventListener("keydown", handleKeyDown);
  try {
    const data = await API.sessions();
    S.sessions  = data.sessions  || [];
    S.campaigns = data.campaigns || [];
    S.filename  = data.filename;
    S.uploadTs  = data.upload_ts;
    S.stats     = data.stats || { p1: 0, p2: 0, p3: 0, total: 0 };
    applyFilter();
  } catch (e) {
    console.error("Init failed:", e);
  }
  render();
}

init();
