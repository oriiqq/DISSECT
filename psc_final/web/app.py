"""
dissect — FastAPI + htmx web dashboard

Run:
    uvicorn web.app:app --reload --port 8741
    open http://localhost:8741
"""
from __future__ import annotations
import io, ipaddress, logging, re, sys, tempfile, zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ingest        import parse_json_export, parse_evtx, parse_evtx_all, reassemble_multipart, stitch_sessions, enrich_session
from core.classifier    import Classifier
from core.fingerprinter import cluster_into_campaigns
from core.baseline      import EnvironmentBaseline
from core.models        import Session, Campaign, LateralMove
from reports.sigma       import generate_sigma_for_sessions, generate_sigma_rules, _TEMPLATES as _SIGMA_TEMPLATES
from reports.yara        import generate_yara_for_sessions
from reports.detections  import generate_detections
from reports.hardening   import generate_hardening
from reports.iocs        import generate_ioc_hub
from reports.navigator   import generate_navigator_layer
from reports.html_report import generate_report
from reports.stix        import generate_stix_bundle

log        = logging.getLogger("psc.web")
BASE_DIR   = Path(__file__).parent
app        = FastAPI(title="dissect", version="1.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates  = Jinja2Templates(directory=str(BASE_DIR / "templates"))
_clf       = Classifier()

_state: dict = {"sessions": [], "campaigns": [], "ts": None, "filename": None,
                "baseline": EnvironmentBaseline(), "proc_events": [], "logon_events": []}

# Per-session analyst triage state: session_id → {status, notes, ts}
_triage: dict = {}

# Matches [PLAINTEXT_CRED:...] markers left by the deobfuscator
_CRED_RE = re.compile(r'\[PLAINTEXT_CRED:([^\]]+)\]')

# IPv4 pattern used across helpers
_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# Module-level geo cache — persists across requests so we don't re-query the same IPs
_geo_cache: dict[str, dict] = {}


async def _geolocate_ips(ips: list[str]) -> list[dict]:
    """
    Geolocate public IPv4 addresses via ip-api.com batch endpoint.
    Private/loopback IPs are silently skipped. Results are cached in _geo_cache.
    """
    if not ips:
        return []

    # Filter to routable public IPs only
    public: list[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_private and not addr.is_loopback and not addr.is_link_local:
                public.append(ip)
        except ValueError:
            pass

    to_query = [ip for ip in public if ip not in _geo_cache]
    if to_query:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    "http://ip-api.com/batch",
                    json=[{"query": ip, "fields": "status,lat,lon,country,city,query"}
                          for ip in to_query[:100]],
                )
                for entry in resp.json():
                    if entry.get("status") == "success":
                        _geo_cache[entry["query"]] = {
                            "lat":     entry["lat"],
                            "lon":     entry["lon"],
                            "country": entry.get("country", ""),
                            "city":    entry.get("city", ""),
                        }
        except Exception:
            pass  # geo lookup is best-effort; globe shows empty if unreachable

    return [{"ip": ip, **_geo_cache[ip]} for ip in public if ip in _geo_cache]


def _extract_creds(sessions: list) -> list[dict]:
    """Scan decoded blocks for plaintext credential markers."""
    creds: list[dict] = []
    seen: set[str] = set()
    for s in sessions:
        for b in s.blocks:
            for m in _CRED_RE.finditer(b.decoded_text):
                val = m.group(1)
                if val not in seen:
                    seen.add(val)
                    creds.append({
                        "value": val,
                        "session_id": s.session_id,
                        "host_id": s.host_id,
                        "timestamp": b.timestamp.strftime('%Y-%m-%d %H:%M:%S') if b.timestamp else None,
                        "block_id": b.block_id,
                    })
    return creds


def _score_breakdown(s) -> dict:
    """Reconstruct the score component breakdown for a session."""
    from core.models import TempoClass
    scores = [b.severity for b in s.blocks if b.severity > 0]
    if not scores:
        return {"max_block_score": 0, "base": 0, "weighted": 0,
                "chains": [], "chain_total": 0, "tempo": 0, "total": 0}

    max_score    = max(scores)
    top3         = sorted(scores, reverse=True)[:3]
    weighted_avg = sum(top3) * 0.7 + (sum(scores) / len(scores)) * 0.3
    techs        = s.technique_set
    chains: list[tuple[str, int]] = []

    if {"AMSI_BYPASS_REFLECT", "DOWNLOAD_CRADLE_WC"}.issubset(techs):
        chains.append(("AMSI bypass + download cradle", 15))
    if "AMSI_BYPASS_REFLECT" in techs and "AMSI_BYPASS_COM" in techs:
        chains.append(("Double AMSI bypass", 8))
    if "REFLECTIVE_INJECT" in techs or "SHELLCODE_MARSHAL" in techs:
        chains.append(("Reflective injection / shellcode", 20))
    if "COBALT_STRIKE" in techs:
        chains.append(("Cobalt Strike beacon pattern", 20))
    if "REVERSE_SHELL" in techs and "DOWNLOAD_CRADLE_WC" in techs:
        chains.append(("Reverse shell + download", 15))
    cred_techs = {"CRED_HARVEST", "DCSYNC_PATTERN", "LSASS_READ", "SAM_DUMP", "KERBEROAST_SPN"}
    if techs & cred_techs and techs & {"AMSI_BYPASS_REFLECT", "AMSI_BYPASS_PATCH", "ETW_PATCH_INLINE"}:
        chains.append(("Credential access + bypass chain", 15))
    lateral_techs = {"LATERAL_PSREMOTING", "LATERAL_WMI_EXEC", "LATERAL_INVOKE_CMD"}
    if techs & lateral_techs and techs & {"DOWNLOAD_CRADLE_WC", "DOWNLOAD_CRADLE_IWR"}:
        chains.append(("Download + lateral movement", 20))
    lolbin_techs = {"LOLBIN_CERTUTIL","LOLBIN_MSHTA","LOLBIN_REGSVR32","LOLBIN_RUNDLL32","LOLBIN_BITSADMIN"}
    if len(techs & lolbin_techs) >= 2:
        chains.append(("LOLBin cluster (2+ tools)", 12))

    chain_total = sum(v for _, v in chains)
    tempo_bonus = 10 if s.tempo.value == "interactive_operator" else 0
    base_c      = round(max_score * 0.4, 1)
    weighted_c  = round(weighted_avg * 0.6, 1)
    total       = round(min(100.0, base_c + weighted_c + chain_total + tempo_bonus), 1)

    return {
        "max_block_score": max_score,
        "base":            base_c,
        "weighted":        weighted_c,
        "chains":          chains,
        "chain_total":     chain_total,
        "tempo":           tempo_bonus,
        "total":           total,
    }


def _host_timeline_events(sessions: list) -> list[dict]:
    """Build percentage-positioned timeline events for the infection spread strip."""
    timed = sorted([(s.start_time, s) for s in sessions if s.start_time], key=lambda x: x[0])
    if not timed:
        return []
    if len(timed) == 1:
        t, s = timed[0]
        return [{"pct": 50.0, "tier": s.alert_tier, "score": round(s.weighted_score),
                 "ts": t.strftime('%H:%M:%S'), "session_id": s.session_id}]
    t_min, t_max = timed[0][0], timed[-1][0]
    span = (t_max - t_min).total_seconds()
    events = []
    for t, s in timed:
        raw_pct = (t - t_min).total_seconds() / span * 100 if span > 0 else 50.0
        events.append({
            "pct":        max(3.0, min(97.0, round(raw_pct, 1))),
            "tier":       s.alert_tier,
            "score":      round(s.weighted_score),
            "ts":         t.strftime('%H:%M:%S'),
            "session_id": s.session_id,
        })
    return events


def _beacon_period_clusters(beaconing: list) -> list[dict]:
    """Group beaconing sessions whose callback periods are within 10% of each other."""
    if not beaconing:
        return []
    sorted_b = sorted(beaconing, key=lambda s: s.beacon_profile.period_seconds)
    clusters: list[dict] = []
    for s in sorted_b:
        period = s.beacon_profile.period_seconds
        placed = False
        for c in clusters:
            ref = c["period"]
            if abs(period - ref) / max(ref, 0.001) <= 0.10:
                c["sessions"].append(s)
                placed = True
                break
        if not placed:
            clusters.append({"period": round(period, 1), "sessions": [s]})
    return [c for c in clusters if len(c["sessions"]) >= 2]


def _beacon_infra_clusters(beaconing: list) -> list[dict]:
    """Cluster beacon C2 IOCs by shared /24 subnet or parent domain."""
    _dom_re = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')
    ip_map:  dict = defaultdict(list)
    dom_map: dict = defaultdict(list)

    for s in beaconing:
        for ioc in s.iocs:
            ioc = ioc.strip()
            if _IP_RE.match(ioc):
                try:
                    subnet = str(ipaddress.ip_network(f"{ioc}/24", strict=False))
                    ip_map[subnet].append((s, ioc))
                except ValueError:
                    pass
            elif _dom_re.match(ioc) and '/' not in ioc:
                parts = ioc.split('.')
                if len(parts) >= 2:
                    parent = '.'.join(parts[-2:])
                    dom_map[parent].append((s, ioc))

    clusters: list[dict] = []
    for subnet, entries in ip_map.items():
        if len({e[0].session_id for e in entries}) >= 2:
            clusters.append({
                "cluster_type": "IP /24",
                "key":      subnet,
                "sessions": list({e[0].session_id: e[0] for e in entries}.values()),
                "iocs":     list(dict.fromkeys(e[1] for e in entries)),
            })
    for parent, entries in dom_map.items():
        if len({e[0].session_id for e in entries}) >= 2:
            clusters.append({
                "cluster_type": "Domain",
                "key":      f"*.{parent}",
                "sessions": list({e[0].session_id: e[0] for e in entries}.values()),
                "iocs":     list(dict.fromkeys(e[1] for e in entries)),
            })
    return sorted(clusters, key=lambda c: -len(c["sessions"]))


def _cred_reuse_map(creds: list, sessions: list, logon_events: list) -> dict | None:
    """
    Cross-reference credential-bearing hosts against subsequent lateral moves
    and outbound logon events to surface potential credential reuse paths.
    """
    if not creds:
        return None

    # Earliest extraction time per host
    host_first_cred: dict[str, datetime] = {}
    for c in creds:
        if c["timestamp"]:
            try:
                ts = datetime.strptime(c["timestamp"], '%Y-%m-%d %H:%M:%S')
                if c["host_id"] not in host_first_cred or ts < host_first_cred[c["host_id"]]:
                    host_first_cred[c["host_id"]] = ts
            except ValueError:
                pass

    if not host_first_cred:
        return None

    source_hosts = sorted(host_first_cred.keys())

    # Lateral moves from credential-bearing hosts (at or after extraction)
    lateral_targets: dict[str, set[str]] = defaultdict(set)
    for s in sessions:
        if s.host_id not in host_first_cred:
            continue
        cred_time = host_first_cred[s.host_id]
        for move in s.lateral_moves:
            if move.timestamp is None:
                lateral_targets[s.host_id].add(move.target_host)
            else:
                move_ts = move.timestamp.replace(tzinfo=None)
                if move_ts >= cred_time:
                    lateral_targets[s.host_id].add(move.target_host)

    # Outbound logon events from credential-bearing hosts (at or after extraction)
    logon_targets: dict[str, set[str]] = defaultdict(set)
    for le in logon_events:
        if le.host_id not in host_first_cred:
            continue
        if le.target_host and le.target_host != le.host_id:
            le_ts = le.timestamp.replace(tzinfo=None)
            if le_ts >= host_first_cred[le.host_id]:
                logon_targets[le.host_id].add(le.target_host)

    all_targets: set[str] = set()
    for h in source_hosts:
        all_targets |= lateral_targets[h]
        all_targets |= logon_targets[h]
    all_targets -= set(source_hosts)

    if not all_targets:
        return None

    target_hosts = sorted(all_targets)
    return {
        "sources":  source_hosts,
        "targets":  target_hosts,
        "lateral":  {h: sorted(lateral_targets[h]) for h in source_hosts},
        "logons":   {h: sorted(logon_targets[h])   for h in source_hosts},
    }


def _detect_lateral_moves(sessions: list[Session]) -> None:
    """
    Cross-session lateral movement detection.
    A lateral move is inferred when two sessions on different hosts share a
    lateral-movement technique and the second session starts within 30 minutes
    of the first.
    """
    LATERAL_TECHS = {
        "LATERAL_PSREMOTING": ("T1021.006", "PSRemoting"),
        "LATERAL_WMI_EXEC":   ("T1021.003", "WMI Exec"),
        "LATERAL_INVOKE_CMD": ("T1021.002", "SMB/PsExec"),
        "COM_LATERAL":        ("T1021.003", "DCOM"),
        "WMIC_REMOTE_EXEC":   ("T1047",     "WMIC Remote"),
    }
    sorted_s = sorted(sessions, key=lambda s: s.start_time or s.start_time or sessions[0].start_time)

    for i, src in enumerate(sorted_s):
        src_lat = src.technique_set & set(LATERAL_TECHS)
        if not src_lat:
            continue
        for dst in sorted_s[i + 1:]:
            if dst.host_id == src.host_id:
                continue
            if not src.end_time or not dst.start_time:
                continue
            delta = (dst.start_time - src.end_time).total_seconds()
            if -60 <= delta <= 1800:  # within 30 min window
                for tech in src_lat:
                    mitre_id, label = LATERAL_TECHS[tech]
                    move = LateralMove(
                        source_host=src.host_id,
                        target_host=dst.host_id,
                        technique=tech,
                        mitre_id=mitre_id,
                        timestamp=dst.start_time,
                        evidence=label,
                    )
                    src.lateral_moves.append(move)

# ── Jinja globals ──────────────────────────────────────────────────────────────
def _tier_cls(t):
    return {"P1_INCIDENT":"tier-p1","P2_ALERT":"tier-p2","P3_WARNING":"tier-p3",
            "INFO":"tier-info","CLEAN":"tier-clean"}.get(t,"tier-clean")

def _sev_cls(l):
    return {"critical":"sev-critical","high":"sev-high",
            "medium":"sev-medium","low":"sev-low"}.get(l,"sev-low")

templates.env.globals["tier_cls"] = _tier_cls
templates.env.globals["sev_cls"]  = _sev_cls
templates.env.filters["has_any"]  = lambda a, b: bool(set(a) & set(b))

def _stats():
    ss = _state["sessions"]
    return {"p1":sum(1 for s in ss if s.alert_tier=="P1_INCIDENT"),
            "p2":sum(1 for s in ss if s.alert_tier=="P2_ALERT"),
            "p3":sum(1 for s in ss if s.alert_tier=="P3_WARNING"),
            "total":len(ss), "campaigns":len(_state["campaigns"])}

def _ctx(request, extra=None):
    """Build template context dict."""
    ctx = {
        "request":   request,
        "sessions":  sorted(_state["sessions"], key=lambda s:-s.weighted_score)[:200],
        "campaigns": _state["campaigns"],
        "stats":     _stats(),
        "upload_ts": _state["ts"],
        "filename":  _state["filename"],
        "page":      "dashboard",
    }
    if extra:
        ctx.update(extra)
    return ctx

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", _ctx(request))

@app.post("/upload", response_class=HTMLResponse)
async def upload(request: Request, file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > 200 * 1024 * 1024:   # 200 MB — EVTX files can be large
        raise HTTPException(413, "File too large (200 MB max)")

    fname  = (file.filename or "").lower()
    is_evtx = fname.endswith(".evtx")
    suffix  = ".evtx" if is_evtx else ".json"

    try:
        # Write to a named temp file — both parsers need a real path on disk
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(content)
            path = Path(tmp.name)

        if is_evtx:
            raw_blocks, proc_events, logon_events = parse_evtx_all(path)
        else:
            raw_blocks = list(parse_json_export(path))
            proc_events, logon_events = [], []

        path.unlink(missing_ok=True)

        if not raw_blocks:
            return HTMLResponse(
                '<div class="error-banner">'
                'No Event ID 4104 records found in that file. '
                'Make sure PowerShell Script Block Logging is enabled '
                'and the file contains Security or PowerShell-Operational events.'
                '</div>'
            )

        blocks   = _clf.classify_batch(reassemble_multipart(raw_blocks))
        sessions = stitch_sessions(blocks)

        # Build a pid→ProcessEvent lookup for parent-process annotation
        pid_map: dict[tuple[str, int], str] = {}
        for pe in proc_events:
            pid_map[(pe.host_id, pe.process_id)] = pe.process_name

        for s in sessions:
            enrich_session(s)
            # Annotate parent process name from 4688 events
            parent_key = (s.host_id, s.process_id)
            if parent_key in pid_map:
                s.parent_process = pid_map[parent_key]
            # Add 4688/logon event IDs seen for this host
            s.event_ids_seen = {pe.event_id for pe in proc_events if pe.host_id == s.host_id}
            s.event_ids_seen |= {le.event_id for le in logon_events if le.host_id == s.host_id}
            # Process tree: events with matching host + matching parent pid
            s.process_tree = [pe for pe in proc_events if pe.host_id == s.host_id][:50]

        # Detect lateral movement: sessions on different hosts sharing techniques
        _detect_lateral_moves(sessions)

        _state.update(
            sessions=sessions,
            campaigns=cluster_into_campaigns(sessions),
            ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            filename=file.filename,
            proc_events=proc_events,
            logon_events=logon_events,
        )

    except ImportError as exc:
        # python-evtx or lxml not installed
        return HTMLResponse(
            '<div class="error-banner">'
            f'EVTX parsing requires python-evtx and lxml: '
            f'<code>pip install python-evtx lxml</code> — {exc}'
            '</div>',
            status_code=500,
        )
    except Exception as exc:
        log.exception("Upload failed: %s", file.filename)
        return HTMLResponse(
            f'<div class="error-banner">Analysis failed: {exc}</div>',
            status_code=500,
        )

    return templates.TemplateResponse(request, "partials/dashboard.html", _ctx(request))

@app.get("/sessions/{session_id}", response_class=HTMLResponse)
async def session_detail(request: Request, session_id: str):
    s = next((x for x in _state["sessions"] if x.session_id == session_id), None)
    if not s: raise HTTPException(404)

    # Logon events within ±5 min of session window
    t0 = (s.start_time - timedelta(minutes=5)) if s.start_time else None
    t1 = ((s.end_time or s.start_time) + timedelta(minutes=5)) if s.start_time else None
    session_logons = (
        [le for le in _state["logon_events"]
         if le.host_id == s.host_id and t0 <= le.timestamp <= t1]
        if t0 and t1 else []
    )

    # Credentials extracted from this session's decoded blocks
    session_creds = []
    for b in s.blocks:
        for m in _CRED_RE.finditer(b.decoded_text):
            session_creds.append({
                "value": m.group(1),
                "block_id": b.block_id,
                "timestamp": b.timestamp.strftime('%Y-%m-%d %H:%M:%S') if b.timestamp else None,
            })

    return templates.TemplateResponse(request, "partials/session_detail.html", {
        "session":         s,
        "bundle":          generate_sigma_rules(s),
        "triage":          _triage.get(session_id, {"status": "unreviewed", "notes": ""}),
        "score_breakdown": _score_breakdown(s),
        "session_logons":  session_logons[:30],
        "session_creds":   session_creds,
    })

@app.get("/detections", response_class=HTMLResponse)
async def detections_page(request: Request):
    bundle = generate_detections(_state["sessions"])
    return templates.TemplateResponse(request, "detections.html", _ctx(request, {
        "page":       "detections",
        "detections": bundle.detections,
    }))

@app.get("/detections/download/sentinel", response_class=PlainTextResponse)
async def detections_kql():
    bundle = generate_detections(_state["sessions"])
    return PlainTextResponse(bundle.to_kql(), media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=dissect_sentinel.kql"})

@app.get("/detections/download/splunk", response_class=PlainTextResponse)
async def detections_spl():
    bundle = generate_detections(_state["sessions"])
    return PlainTextResponse(bundle.to_spl(), media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=dissect_splunk.spl"})

@app.get("/detections/download/qradar", response_class=PlainTextResponse)
async def detections_aql():
    bundle = generate_detections(_state["sessions"])
    return PlainTextResponse(bundle.to_aql(), media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=dissect_qradar.aql"})

@app.get("/hardening", response_class=HTMLResponse)
async def hardening_page(request: Request):
    hdg = generate_hardening(_state["sessions"])
    has_triggered = any(e.triggered for e in hdg)
    has_general   = any(e.general   for e in hdg)
    return templates.TemplateResponse(request, "hardening.html", _ctx(request, {
        "page":          "hardening",
        "hardening":     hdg,
        "has_triggered": has_triggered,
        "has_general":   has_general,
    }))

@app.get("/yara", response_class=HTMLResponse)
async def yara_page(request: Request):
    bundle = generate_yara_for_sessions(_state["sessions"])
    return templates.TemplateResponse(request, "yara.html", _ctx(request, {
        "page":       "yara",
        "yara_text":  bundle.to_yara() if bundle.rules else "",
        "rule_count": len(bundle.rules),
    }))

@app.get("/yara/download", response_class=PlainTextResponse)
async def yara_download():
    bundle = generate_yara_for_sessions(_state["sessions"])
    return PlainTextResponse(
        bundle.to_yara(),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=dissect_rules.yar"},
    )

@app.get("/sigma", response_class=HTMLResponse)
async def sigma_page(request: Request):
    bundle = generate_sigma_for_sessions(_state["sessions"])
    return templates.TemplateResponse(request, "sigma.html", _ctx(request, {
        "page":        "sigma",
        "sigma_rules": bundle.rules,
        "rule_count":  len(bundle.rules),
    }))

@app.get("/sigma/download", response_class=PlainTextResponse)
async def sigma_download():
    bundle = generate_sigma_for_sessions(_state["sessions"])
    if not bundle.rules:
        return PlainTextResponse("# No rules — run an analysis first.\n")
    return PlainTextResponse(bundle.to_combined_yaml(), media_type="text/yaml",
        headers={"Content-Disposition": "attachment; filename=dissect_sigma.yml"})

@app.get("/detections/download/elastic", response_class=PlainTextResponse)
async def detections_eql():
    bundle = generate_detections(_state["sessions"])
    return PlainTextResponse(bundle.to_eql(), media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=dissect_elastic.eql"})

@app.get("/detections/download/chronicle", response_class=PlainTextResponse)
async def detections_yaral():
    bundle = generate_detections(_state["sessions"])
    return PlainTextResponse(bundle.to_yaral(), media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=dissect_chronicle.yaral"})

@app.get("/report/download", response_class=HTMLResponse)
async def report_download():
    if not _state["sessions"]: raise HTTPException(404, "No analysis loaded")
    html = generate_report(_state["sessions"], campaigns=_state["campaigns"])
    return HTMLResponse(html, headers={"Content-Disposition":"attachment; filename=dissect_report.html"})

@app.get("/iocs", response_class=HTMLResponse)
async def iocs_page(request: Request):
    bundle = generate_ioc_hub(_state["sessions"])
    return templates.TemplateResponse(request, "iocs.html", _ctx(request, {
        "page":       "iocs",
        "ioc_entries": bundle.entries,
        "ioc_counts":  bundle.counts(),
        "total_iocs":  len(bundle.entries),
    }))

@app.get("/iocs/download/csv", response_class=PlainTextResponse)
async def iocs_csv():
    bundle = generate_ioc_hub(_state["sessions"])
    return PlainTextResponse(bundle.to_csv(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dissect_iocs.csv"})

@app.get("/iocs/download/txt", response_class=PlainTextResponse)
async def iocs_txt():
    bundle = generate_ioc_hub(_state["sessions"])
    return PlainTextResponse(bundle.to_text(), media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=dissect_iocs.txt"})

@app.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request):
    from itertools import groupby

    sessions_with_ts = [s for s in _state["sessions"] if s.start_time]
    sessions_sorted  = sorted(sessions_with_ts, key=lambda s: s.start_time)

    date_groups:      list[dict] = []
    min_label = max_label = ""
    unique_host_count = 0

    # Build temporal heatmap: (dow 0=Mon, hour) → {count, max_score, max_tier}
    heatmap: dict[tuple, dict] = {}
    for s in sessions_sorted:
        key = (s.start_time.weekday(), s.start_time.hour)
        if key not in heatmap:
            heatmap[key] = {"count": 0, "max_score": 0.0, "max_tier": "CLEAN"}
        heatmap[key]["count"]    += 1
        heatmap[key]["max_score"] = max(heatmap[key]["max_score"], s.weighted_score)
        tier_order = {"P1_INCIDENT": 4, "P2_ALERT": 3, "P3_WARNING": 2, "INFO": 1, "CLEAN": 0}
        if tier_order.get(s.alert_tier, 0) > tier_order.get(heatmap[key]["max_tier"], 0):
            heatmap[key]["max_tier"] = s.alert_tier
    # Serialise for JS: list of {dow, hour, count, score, tier}
    heatmap_cells = [
        {"dow": k[0], "hour": k[1], **v}
        for k, v in heatmap.items()
    ]

    if sessions_sorted:
        unique_host_count = len({s.host_id for s in sessions_sorted})
        min_label = sessions_sorted[0].start_time.strftime("%Y-%m-%d %H:%M UTC")
        max_label = sessions_sorted[-1].start_time.strftime("%Y-%m-%d %H:%M UTC")

        for day, group_iter in groupby(sessions_sorted, key=lambda s: s.start_time.date()):
            date_groups.append({
                "label":    day.strftime("%A, %B %d %Y"),
                "sessions": list(group_iter),
            })

    return templates.TemplateResponse(request, "timeline.html", _ctx(request, {
        "page":              "timeline",
        "date_groups":       date_groups,
        "min_label":         min_label,
        "max_label":         max_label,
        "total_sessions":    len(sessions_sorted),
        "unique_host_count": unique_host_count,
        "heatmap_cells":     heatmap_cells,
    }))

@app.get("/summary", response_class=HTMLResponse)
async def summary_page(request: Request):
    sessions = _state["sessions"]
    if not sessions:
        return templates.TemplateResponse(request, "summary.html", _ctx(request, {
            "page": "summary", "has_data": False,
        }))

    tier_counts  = Counter(s.alert_tier for s in sessions)
    top_sessions = sorted(sessions, key=lambda s: -s.weighted_score)[:5]

    mitre_counts: Counter = Counter()
    all_techniques: set[str] = set()
    for s in sessions:
        for b in s.blocks:
            for f in b.findings:
                if f.mitre_id:
                    mitre_counts[f.mitre_id] += 1
                all_techniques.add(f.technique_id)

    # Map MITRE IDs to ATT&CK tactics for the heatmap
    _TACTIC_ORDER = [
        ("Execution",        ["T1059", "T1047", "T1204"]),
        ("Defense Evasion",  ["T1562", "T1140", "T1218", "T1027"]),
        ("Persistence",      ["T1547", "T1546", "T1053", "T1505"]),
        ("Priv. Escalation", ["T1055", "T1134", "T1068"]),
        ("Cred. Access",     ["T1003", "T1558", "T1555", "T1552"]),
        ("Lateral Movement", ["T1021", "T1570"]),
        ("Command & Control",["T1105", "T1197", "T1071", "T1095"]),
    ]
    tactic_breakdown: list[dict] = []
    used_midkeys: set[str] = set()
    for tactic_name, prefixes in _TACTIC_ORDER:
        hits = {}
        for mid, cnt in mitre_counts.items():
            base = mid.split(".")[0]
            if base in prefixes and mid not in used_midkeys:
                hits[mid] = cnt
                used_midkeys.add(mid)
        tactic_breakdown.append({
            "name":   tactic_name,
            "hits":   hits,
            "active": len(hits) > 0,
            "total":  sum(hits.values()),
        })

    all_iocs    = [v for s in sessions for v in s.iocs]
    from reports.iocs import _ioc_type
    ioc_type_counts = Counter(_ioc_type(v) for v in all_iocs if v.strip())
    unique_iocs = len(set(v.strip() for s in sessions for v in s.iocs if v.strip()))
    unique_hosts = len({s.host_id for s in sessions})

    if tier_counts.get("P1_INCIDENT", 0) > 0:
        risk_level, risk_color, risk_bg = "CRITICAL", "var(--red)", "var(--red-bg)"
    elif tier_counts.get("P2_ALERT", 0) > 0:
        risk_level, risk_color, risk_bg = "HIGH", "var(--amber)", "var(--amber-bg)"
    elif tier_counts.get("P3_WARNING", 0) > 0:
        risk_level, risk_color, risk_bg = "MEDIUM", "var(--teal)", "var(--teal-bg)"
    else:
        risk_level, risk_color, risk_bg = "LOW", "var(--blue)", "var(--blue-bg)"

    return templates.TemplateResponse(request, "summary.html", _ctx(request, {
        "page":             "summary",
        "has_data":         True,
        "risk_level":       risk_level,
        "risk_color":       risk_color,
        "risk_bg":          risk_bg,
        "tier_counts":      tier_counts,
        "top_sessions":     top_sessions,
        "mitre_counts":     dict(sorted(mitre_counts.items(), key=lambda x: -x[1])),
        "tactic_breakdown": tactic_breakdown,
        "all_techniques":   sorted(all_techniques),
        "ioc_type_counts":  ioc_type_counts,
        "unique_iocs":      unique_iocs,
        "unique_hosts":     unique_hosts,
    }))

@app.get("/navigator/download")
async def navigator_download():
    if not _state["sessions"]:
        raise HTTPException(404, "No analysis loaded")
    return PlainTextResponse(
        generate_navigator_layer(_state["sessions"]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=dissect_navigator.json"},
    )

@app.delete("/state", response_class=HTMLResponse)
async def clear(request: Request):
    _state.update(sessions=[], campaigns=[], ts=None, filename=None)
    return templates.TemplateResponse(request, "partials/dashboard.html", _ctx(request))

@app.get("/api/stats")
async def api_stats():
    return _stats()


# ── v2 JSON API ────────────────────────────────────────────────────────────────

def _session_summary(s) -> dict:
    return {
        "session_id":          s.session_id,
        "host_id":             s.host_id,
        "process_id":          s.process_id,
        "alert_tier":          s.alert_tier,
        "weighted_score":      round(s.weighted_score, 1),
        "start_time":          s.start_time.isoformat() if s.start_time else None,
        "end_time":            s.end_time.isoformat() if s.end_time else None,
        "duration_seconds":    round(s.duration_seconds, 1),
        "technique_set":       sorted(s.technique_set),
        "block_count":         len(s.blocks),
        "ioc_count":           len(s.iocs),
        "ti_hit_count":        len(s.ti_hits),
        "lateral_move_count":  len(s.lateral_moves),
        "has_beacon":          bool(s.beacon_profile and s.beacon_profile.is_beacon),
        "campaign_id":         s.campaign_id,
        "parent_process":      s.parent_process,
        "tempo":               s.tempo.value,
        "deobfuscation_passes":s.deobfuscation_passes,
        "max_severity":        s.max_severity,
    }

def _session_full(s) -> dict:
    d = _session_summary(s)
    d.update({
        "iocs": s.iocs[:60],
        "ti_hits": [
            {"ioc_value": h.ioc_value, "ioc_type": h.ioc_type, "source": h.source,
             "malware_name": h.malware_name, "tags": h.tags, "confidence": h.confidence,
             "first_seen": h.first_seen, "threat_type": h.threat_type}
            for h in s.ti_hits
        ],
        "lateral_moves": [
            {"source_host": m.source_host, "target_host": m.target_host,
             "technique": m.technique, "mitre_id": m.mitre_id, "evidence": m.evidence,
             "timestamp": m.timestamp.isoformat() if m.timestamp else None}
            for m in s.lateral_moves
        ],
        "beacon_profile": {
            "period_seconds": s.beacon_profile.period_seconds,
            "jitter_pct":     round(s.beacon_profile.jitter_pct, 3),
            "confidence":     round(s.beacon_profile.confidence, 3),
            "sample_count":   s.beacon_profile.sample_count,
            "framework_hint": s.beacon_profile.framework_hint,
            "is_beacon":      s.beacon_profile.is_beacon,
        } if s.beacon_profile else None,
        "process_tree": [
            {"event_id": pe.event_id,
             "timestamp": pe.timestamp.isoformat() if pe.timestamp else None,
             "process_id": pe.process_id, "parent_pid": pe.parent_pid,
             "process_name": pe.process_name, "parent_name": pe.parent_name,
             "command_line": pe.command_line[:200], "user": pe.user,
             "integrity": pe.integrity, "logon_id": pe.logon_id}
            for pe in s.process_tree[:30]
        ],
        "blocks": [
            {"block_id": b.block_id,
             "timestamp": b.timestamp.isoformat() if b.timestamp else None,
             "path": b.path, "entropy": round(b.entropy, 2), "severity": b.severity,
             "decoded_text": b.decoded_text[:1200],
             "raw_text": b.raw_text[:400] if b.raw_text != b.decoded_text else None,
             "findings": [
                 {"technique_id": f.technique_id, "mitre_id": f.mitre_id,
                  "severity": f.severity, "rule_name": f.rule_name,
                  "matched_text": f.matched_text[:200], "context": f.context,
                  "confidence": round(f.confidence, 2)}
                 for f in b.findings
             ]}
            for b in s.blocks
        ],
        "score_breakdown": _score_breakdown(s),
        "credentials": _extract_creds([s]),
    })
    return d

@app.get("/api/sessions")
async def api_sessions_list():
    sessions = sorted(_state["sessions"], key=lambda s: -s.weighted_score)[:200]
    return JSONResponse({
        "sessions": [_session_summary(s) for s in sessions],
        "campaigns": [
            {"campaign_id": c.campaign_id, "session_count": len(c.sessions),
             "host_count": len(c.host_ids), "is_confirmed": c.is_confirmed,
             "peak_severity": c.peak_severity,
             "first_seen": c.first_seen.isoformat() if c.first_seen else None,
             "last_seen":  c.last_seen.isoformat()  if c.last_seen  else None}
            for c in _state["campaigns"]
        ],
        "filename":  _state["filename"],
        "upload_ts": _state["ts"],
        "stats":     _stats(),
    })

@app.get("/api/sessions/{session_id}")
async def api_session_detail(session_id: str):
    s = next((x for x in _state["sessions"] if x.session_id == session_id), None)
    if not s:
        raise HTTPException(404)
    sigma_bundle = generate_sigma_rules(s)
    d = _session_full(s)
    d["sigma_rules"] = [
        {"rule_id": r.rule_id, "title": r.title, "level": r.level,
         "mitre_id": r.mitre_id, "tags": r.tags, "yaml": r.to_yaml()}
        for r in sigma_bundle.rules
    ]
    return JSONResponse(d)

@app.get("/api/iocs")
async def api_iocs_list():
    bundle = generate_ioc_hub(_state["sessions"])
    return JSONResponse({
        "entries": [
            {"value": e.value, "ioc_type": e.ioc_type,
             "count": e.count, "session_count": len(e.sessions)}
            for e in bundle.entries
        ],
        "counts": dict(bundle.counts()),
        "total":  len(bundle.entries),
    })

@app.get("/api/ti")
async def api_ti_list():
    from core.threat_intel import enrich_with_ti
    sessions = _state["sessions"]
    for s in sessions:
        if s.iocs and not s.ti_hits:
            try:
                enrich_with_ti(s, max_iocs=15)
            except Exception as exc:
                log.debug("TI enrichment failed: %s", exc)
    all_hits = [hit for s in sessions for hit in s.ti_hits]
    hit_counts: dict[str, int] = {}
    for h in all_hits:
        hit_counts[h.source] = hit_counts.get(h.source, 0) + 1
    return JSONResponse({
        "hits": [
            {"ioc_value": h.ioc_value, "ioc_type": h.ioc_type, "source": h.source,
             "malware_name": h.malware_name, "tags": h.tags, "confidence": h.confidence,
             "first_seen": h.first_seen, "threat_type": h.threat_type}
            for h in all_hits
        ],
        "hit_counts": hit_counts,
        "total": len(all_hits),
    })

@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    """Same processing as /upload, returns JSON state for v2."""
    content = await file.read()
    if len(content) > 200 * 1024 * 1024:
        return JSONResponse({"error": "File too large (200 MB max)"}, status_code=413)
    fname   = (file.filename or "").lower()
    is_evtx = fname.endswith(".evtx")
    suffix  = ".evtx" if is_evtx else ".json"
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(content)
            path = Path(tmp.name)
        if is_evtx:
            raw_blocks, proc_events, logon_events = parse_evtx_all(path)
        else:
            raw_blocks = list(parse_json_export(path))
            proc_events, logon_events = [], []
        path.unlink(missing_ok=True)
        if not raw_blocks:
            return JSONResponse({"error": "No Event ID 4104 records found."}, status_code=422)
        blocks   = _clf.classify_batch(reassemble_multipart(raw_blocks))
        sessions = stitch_sessions(blocks)
        pid_map: dict[tuple[str, int], str] = {}
        for pe in proc_events:
            pid_map[(pe.host_id, pe.process_id)] = pe.process_name
        for s in sessions:
            enrich_session(s)
            parent_key = (s.host_id, s.process_id)
            if parent_key in pid_map:
                s.parent_process = pid_map[parent_key]
            s.event_ids_seen = {pe.event_id for pe in proc_events if pe.host_id == s.host_id}
            s.event_ids_seen |= {le.event_id for le in logon_events if le.host_id == s.host_id}
            s.process_tree = [pe for pe in proc_events if pe.host_id == s.host_id][:50]
        _detect_lateral_moves(sessions)
        _state.update(
            sessions=sessions,
            campaigns=cluster_into_campaigns(sessions),
            ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            filename=file.filename,
            proc_events=proc_events,
            logon_events=logon_events,
        )
    except Exception as exc:
        log.exception("Upload failed: %s", file.filename)
        return JSONResponse({"error": str(exc)}, status_code=500)
    sorted_sessions = sorted(_state["sessions"], key=lambda s: -s.weighted_score)[:200]
    return JSONResponse({
        "sessions":  [_session_summary(s) for s in sorted_sessions],
        "campaigns": [],
        "filename":  _state["filename"],
        "upload_ts": _state["ts"],
        "stats":     _stats(),
    })

@app.get("/v2", response_class=HTMLResponse)
async def v2_index(request: Request):
    return templates.TemplateResponse(request, "v2.html", {"request": request})


@app.get("/stix/download")
async def stix_download():
    if not _state["sessions"]:
        raise HTTPException(404, "No analysis loaded")
    return PlainTextResponse(
        generate_stix_bundle(_state["sessions"]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=dissect_stix.json"},
    )


@app.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(request: Request):
    from core.threat_intel import enrich_with_ti
    sessions = _state["sessions"]
    # Only enrich sessions with IOCs that haven't been enriched yet
    for s in sessions:
        if s.iocs and not s.ti_hits:
            try:
                enrich_with_ti(s, max_iocs=15)
            except Exception as exc:
                log.debug("TI enrichment failed for %s: %s", s.session_id, exc)

    all_hits = [hit for s in sessions for hit in s.ti_hits]
    hit_counts = {}
    for h in all_hits:
        hit_counts[h.source] = hit_counts.get(h.source, 0) + 1

    return templates.TemplateResponse(request, "threat_intel.html", _ctx(request, {
        "page":       "threat_intel",
        "ti_hits":    all_hits,
        "hit_counts": hit_counts,
        "total_hits": len(all_hits),
    }))


@app.get("/hosts", response_class=HTMLResponse)
async def hosts_page(request: Request):
    host_map: dict = defaultdict(list)
    for s in _state["sessions"]:
        host_map[s.host_id].append(s)

    tier_order = {"P1_INCIDENT": 4, "P2_ALERT": 3, "P3_WARNING": 2, "INFO": 1, "CLEAN": 0}
    hosts = []
    for host_id, sessions in host_map.items():
        ss = sorted(sessions, key=lambda s: -s.weighted_score)
        all_techs: set = set()
        for s in ss:
            all_techs |= s.technique_set
        max_tier = max(ss, key=lambda s: tier_order.get(s.alert_tier, 0)).alert_tier
        sigma_covered = set(_SIGMA_TEMPLATES.keys())
        hosts.append({
            "host_id":          host_id,
            "sessions":         ss,
            "max_tier":         max_tier,
            "session_count":    len(ss),
            "technique_count":  len(all_techs),
            "techniques":       sorted(all_techs),
            "p1_count":         sum(1 for s in ss if s.alert_tier == "P1_INCIDENT"),
            "p2_count":         sum(1 for s in ss if s.alert_tier == "P2_ALERT"),
            "p3_count":         sum(1 for s in ss if s.alert_tier == "P3_WARNING"),
            "max_score":        max(s.weighted_score for s in ss),
            "ioc_count":        len({ioc for s in ss for ioc in s.iocs}),
            "first_seen":       min((s.start_time for s in ss if s.start_time), default=None),
            "last_seen":        max(((s.end_time or s.start_time) for s in ss if s.start_time), default=None),
            "timeline_events":  _host_timeline_events(ss),
            "sigma_gaps":       sorted(all_techs - sigma_covered),
        })
    hosts.sort(key=lambda h: (-tier_order.get(h["max_tier"], 0), -h["max_score"]))

    return templates.TemplateResponse(request, "hosts.html", _ctx(request, {
        "page": "hosts", "hosts": hosts,
    }))


@app.get("/beacons", response_class=HTMLResponse)
async def beacons_page(request: Request):
    beaconing = [s for s in _state["sessions"] if s.beacon_profile and s.beacon_profile.is_beacon]
    fw_groups: dict = defaultdict(list)
    for s in beaconing:
        fw_groups[s.beacon_profile.framework_hint or "unknown"].append(s)

    # Extract unique public C2 IPs from beacon IOCs for globe widget
    c2_ips = list(dict.fromkeys(
        ioc.strip() for s in beaconing for ioc in s.iocs
        if _IP_RE.match(ioc.strip())
    ))
    c2_geo_points = await _geolocate_ips(c2_ips)

    return templates.TemplateResponse(request, "beacons.html", _ctx(request, {
        "page":              "beacons",
        "beaconing":         sorted(beaconing, key=lambda s: -s.beacon_profile.confidence),
        "framework_groups":  dict(fw_groups),
        "beacon_count":      len(beaconing),
        "period_clusters":   _beacon_period_clusters(beaconing),
        "infra_clusters":    _beacon_infra_clusters(beaconing),
        "c2_geo_points":     c2_geo_points,
    }))


@app.get("/credentials", response_class=HTMLResponse)
async def credentials_page(request: Request):
    creds = _extract_creds(_state["sessions"])
    return templates.TemplateResponse(request, "credentials.html", _ctx(request, {
        "page":         "credentials",
        "credentials":  creds,
        "cred_count":   len(creds),
        "reuse_matrix": _cred_reuse_map(creds, _state["sessions"], _state["logon_events"]),
    }))


_TACTIC_FOR: dict[str, str] = {
    "T1059": "Execution",
    "T1047": "Execution",
    "T1053": "Persistence",
    "T1546": "Persistence",
    "T1547": "Persistence",
    "T1055": "Priv. Escalation",
    "T1562": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1197": "Defense Evasion",
    "T1218": "Defense Evasion",
    "T1105": "C&C",
    "T1021": "Lateral Movement",
    "T1003": "Credential Access",
    "T1558": "Credential Access",
    "T1555": "Credential Access",
}
_TACTIC_ORDER = [
    "Execution", "Persistence", "Priv. Escalation",
    "Defense Evasion", "Credential Access", "Lateral Movement", "C&C",
]


@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    from reports.iocs import generate_ioc_hub
    sessions = _state["sessions"]
    has_data = bool(sessions)

    _empty = {
        "page": "analytics", "has_data": False, "sessions": [],
        "tier_counts": {}, "all_scores": [], "scores_over_time": [],
        "technique_counts": {}, "tactic_rows": [], "host_risks": [],
        "tempo_counts": {}, "ioc_type_counts": {}, "top_iocs": [],
        "dur_buckets": [], "dur_labels": [],
        "sigma_pct": 0, "sigma_covered_count": 0, "total_techniques": 0,
        "beacon_count": 0, "unique_iocs": 0,
    }
    if not has_data:
        return templates.TemplateResponse(request, "analytics.html", _ctx(request, _empty))

    tier_counts = dict(Counter(s.alert_tier for s in sessions))
    all_scores  = [round(s.weighted_score, 1) for s in sessions]

    sot = sorted((s for s in sessions if s.start_time), key=lambda s: s.start_time)
    scores_over_time = [{"ts": s.start_time.isoformat(), "score": round(s.weighted_score, 1)}
                        for s in sot]

    tech_ctr: Counter = Counter()
    for s in sessions:
        for t in s.technique_set:
            tech_ctr[t] += 1
    technique_counts = [{"tech": k, "count": v} for k, v in tech_ctr.most_common(12)]

    tactic_hits: dict[str, set] = defaultdict(set)
    tactic_total: dict[str, int] = defaultdict(int)
    for prefix, tac in _TACTIC_FOR.items():
        tactic_total[tac] += 1
    for s in sessions:
        for b in s.blocks:
            for f in b.findings:
                tac = _TACTIC_FOR.get(f.mitre_id[:5])
                if tac:
                    tactic_hits[tac].add(s.session_id)
    tactic_rows = [
        {"name": tac, "count": len(tactic_hits.get(tac, set())),
         "total": tactic_total[tac], "active": tac in tactic_hits}
        for tac in _TACTIC_ORDER
    ]

    host_map: dict[str, dict] = {}
    for s in sessions:
        h = host_map.setdefault(s.host_id, {"host_id": s.host_id, "p1": 0, "p2": 0, "p3": 0, "max_score": 0.0})
        if s.alert_tier == "P1_INCIDENT":  h["p1"] += 1
        elif s.alert_tier == "P2_ALERT":   h["p2"] += 1
        elif s.alert_tier == "P3_WARNING": h["p3"] += 1
        if s.weighted_score > h["max_score"]:
            h["max_score"] = round(s.weighted_score, 1)
    host_risks = sorted(host_map.values(),
                        key=lambda h: -(h["p1"] * 3 + h["p2"] * 2 + h["p3"]))[:12]

    tempo_counts = dict(Counter(
        s.tempo.value if hasattr(s.tempo, "value") else str(s.tempo) for s in sessions
    ))

    ioc_bundle     = generate_ioc_hub(sessions)
    ioc_type_counts = ioc_bundle.counts()
    unique_iocs    = len(ioc_bundle.entries)
    top_iocs       = [{"value": e.value, "ioc_type": e.ioc_type, "count": e.count}
                      for e in ioc_bundle.entries[:10]]

    dur_labels     = ["0–30s", "30s–2m", "2–10m", "10–30m", "30m+"]
    dur_buckets    = [0, 0, 0, 0, 0]
    for s in sessions:
        d = s.duration_seconds
        if d < 30:    dur_buckets[0] += 1
        elif d < 120: dur_buckets[1] += 1
        elif d < 600: dur_buckets[2] += 1
        elif d < 1800: dur_buckets[3] += 1
        else:          dur_buckets[4] += 1

    sigma_covered      = set(_SIGMA_TEMPLATES.keys())
    all_techs: set[str] = set()
    for s in sessions:
        all_techs |= s.technique_set
    sigma_covered_count = len(all_techs & sigma_covered)
    total_techniques    = len(all_techs)
    sigma_pct = round(sigma_covered_count / total_techniques * 100, 1) if total_techniques else 0.0

    beacon_count = sum(1 for s in sessions if s.beacon_profile and s.beacon_profile.is_beacon)

    return templates.TemplateResponse(request, "analytics.html", _ctx(request, {
        "page":               "analytics",
        "has_data":           True,
        "sessions":           sessions,
        "tier_counts":        tier_counts,
        "all_scores":         all_scores,
        "scores_over_time":   scores_over_time,
        "technique_counts":   technique_counts,
        "tactic_rows":        tactic_rows,
        "host_risks":         host_risks,
        "tempo_counts":       tempo_counts,
        "ioc_type_counts":    ioc_type_counts,
        "top_iocs":           top_iocs,
        "dur_buckets":        dur_buckets,
        "dur_labels":         dur_labels,
        "sigma_pct":          sigma_pct,
        "sigma_covered_count": sigma_covered_count,
        "total_techniques":   total_techniques,
        "beacon_count":       beacon_count,
        "unique_iocs":        unique_iocs,
    }))


@app.get("/api/search")
async def api_search(q: str = ""):
    if not q or len(q) < 2:
        return JSONResponse({"results": [], "total": 0})
    q_lower = q.lower()
    results = []
    for s in _state["sessions"]:
        matching: list[dict] = []
        for b in s.blocks:
            if q_lower in b.decoded_text.lower():
                idx   = b.decoded_text.lower().find(q_lower)
                start = max(0, idx - 60)
                end   = min(len(b.decoded_text), idx + len(q) + 60)
                matching.append({
                    "block_id":     b.block_id,
                    "timestamp":    b.timestamp.isoformat() if b.timestamp else None,
                    "context":      b.decoded_text[start:end],
                    "match_offset": idx - start,
                    "match_len":    len(q),
                })
        if matching:
            results.append({
                "session_id":     s.session_id,
                "host_id":        s.host_id,
                "process_id":     s.process_id,
                "alert_tier":     s.alert_tier,
                "weighted_score": round(s.weighted_score, 1),
                "matching_blocks": matching[:5],
                "total_matches":  len(matching),
            })
    results.sort(key=lambda r: -r["weighted_score"])
    return JSONResponse({"results": results[:50], "total": len(results), "query": q})


@app.get("/api/pivot")
async def api_pivot(ioc: str = "", technique: str = ""):
    sessions = _state["sessions"]
    if ioc:
        q = ioc.lower()
        matching = [s for s in sessions if any(q in i.lower() for i in s.iocs)]
        ptype, pval = "ioc", ioc
    elif technique:
        matching = [s for s in sessions if technique.upper() in s.technique_set]
        ptype, pval = "technique", technique
    else:
        return JSONResponse({"error": "Provide ioc or technique param"}, status_code=400)
    return JSONResponse({
        "sessions":    [_session_summary(s) for s in matching],
        "total":       len(matching),
        "pivot_type":  ptype,
        "pivot_value": pval,
    })


@app.get("/api/triage/{session_id}")
async def api_get_triage(session_id: str):
    return JSONResponse(_triage.get(session_id, {"status": "unreviewed", "notes": ""}))


@app.post("/api/triage/{session_id}")
async def api_set_triage(session_id: str, request: Request):
    body = await request.json()
    _triage[session_id] = {
        "status": body.get("status", "unreviewed"),
        "notes":  body.get("notes", ""),
        "ts":     datetime.now(timezone.utc).isoformat(),
    }
    return JSONResponse({"ok": True})


@app.get("/sessions/{session_id}/export")
async def session_export(session_id: str):
    s = next((x for x in _state["sessions"] if x.session_id == session_id), None)
    if not s: raise HTTPException(404)
    import json as _json
    sigma_bundle = generate_sigma_rules(s)
    triage = _triage.get(session_id, {})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        data = _session_full(s)
        data["triage"] = triage
        zf.writestr("session_info.json", _json.dumps(data, indent=2, default=str))
        if s.iocs:
            zf.writestr("iocs.txt", "\n".join(s.iocs))
        if sigma_bundle.rules:
            zf.writestr("sigma_rules.yml", sigma_bundle.to_combined_yaml())
        for i, b in enumerate(s.blocks, 1):
            zf.writestr(f"blocks/block_{i:02d}_decoded.ps1", b.decoded_text)
            if b.raw_text != b.decoded_text:
                zf.writestr(f"blocks/block_{i:02d}_raw.ps1", b.raw_text)
        if triage.get("notes"):
            zf.writestr("analyst_notes.txt",
                        f"Status: {triage.get('status','')}\nTimestamp: {triage.get('ts','')}\n\n{triage['notes']}")
    buf.seek(0)
    from fastapi.responses import StreamingResponse
    return StreamingResponse(buf, media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=dissect_{session_id[:24]}.zip"})


@app.get("/lateral", response_class=HTMLResponse)
async def lateral_page(request: Request):
    sessions = _state["sessions"]
    all_moves = [m for s in sessions for m in s.lateral_moves]

    # Build unique node list and edge list for the graph
    hosts = sorted({s.host_id for s in sessions})
    host_tiers = {}
    for s in sessions:
        existing = host_tiers.get(s.host_id)
        if existing is None or s.weighted_score > (host_tiers.get(s.host_id + "_score", 0)):
            host_tiers[s.host_id] = s.alert_tier
            host_tiers[s.host_id + "_score"] = s.weighted_score

    nodes = [{"id": h, "tier": host_tiers.get(h, "CLEAN")} for h in hosts]
    edges = []
    seen_edges: set[tuple] = set()
    for move in all_moves:
        key = (move.source_host, move.target_host, move.technique)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({
                "source": move.source_host,
                "target": move.target_host,
                "technique": move.technique,
                "mitre_id": move.mitre_id,
                "evidence": move.evidence,
                "ts": move.timestamp.strftime("%H:%M:%S") if move.timestamp else "",
            })

    return templates.TemplateResponse(request, "lateral.html", _ctx(request, {
        "page":        "lateral",
        "nodes":       nodes,
        "edges":       edges,
        "all_moves":   all_moves,
        "host_count":  len(hosts),
        "move_count":  len(edges),
    }))


# ─── Combined page: Rules (Detection + YARA + Sigma) ──────────────────────────
@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    sessions = _state["sessions"]
    det_bundle   = generate_detections(sessions)
    yara_bundle  = generate_yara_for_sessions(sessions)
    sigma_bundle = generate_sigma_for_sessions(sessions)
    filename     = _state.get("filename") or ""
    return templates.TemplateResponse(request, "rules.html", _ctx(request, {
        "page":        "rules",
        "detections":  det_bundle.detections,
        "yara_text":   yara_bundle.to_yara() if yara_bundle.rules else "",
        "rule_count":  len(yara_bundle.rules),
        "sigma_rules": sigma_bundle.rules,
        "filename":    filename,
    }))


# ─── Combined page: Intelligence (IOC Hub + Threat Intel) ─────────────────────
@app.get("/intelligence", response_class=HTMLResponse)
async def intelligence_page(request: Request):
    from core.threat_intel import enrich_with_ti
    sessions = _state["sessions"]
    for s in sessions:
        if s.iocs and not s.ti_hits:
            try:
                enrich_with_ti(s, max_iocs=15)
            except Exception as exc:
                log.debug("TI enrichment failed for %s: %s", s.session_id, exc)

    ioc_bundle = generate_ioc_hub(sessions)
    all_hits   = [hit for s in sessions for hit in s.ti_hits]
    hit_counts: dict = {}
    for h in all_hits:
        hit_counts[h.source] = hit_counts.get(h.source, 0) + 1

    _TIER_ORD = {"P1_INCIDENT": 4, "P2_ALERT": 3, "P3_WARNING": 2, "INFO": 1, "CLEAN": 0}
    session_tier = {s.session_id: s.alert_tier for s in sessions}
    ioc_graph_nodes = []
    for e in ioc_bundle.entries[:50]:
        max_tier = max(
            (session_tier.get(sid, "CLEAN") for sid in e.sessions),
            key=lambda t: _TIER_ORD.get(t, 0),
            default="CLEAN",
        )
        ioc_graph_nodes.append({
            "value":    e.value,
            "type":     e.ioc_type,
            "count":    e.count,
            "sessions": e.sessions,
            "max_tier": max_tier,
        })

    return templates.TemplateResponse(request, "intelligence.html", _ctx(request, {
        "page":             "intelligence",
        "ioc_entries":      ioc_bundle.entries,
        "ioc_counts":       ioc_bundle.counts(),
        "total_iocs":       len(ioc_bundle.entries),
        "ioc_graph_nodes":  ioc_graph_nodes,
        "ti_hits":          all_hits,
        "hit_counts":       hit_counts,
        "total_hits":       len(all_hits),
        "filename":         _state.get("filename") or "",
    }))


# ─── Combined page: Investigation (Lateral + Timeline + Summary) ──────────────
@app.get("/investigation", response_class=HTMLResponse)
async def investigation_page(request: Request):
    from itertools import groupby
    sessions = _state["sessions"]

    # ── Lateral movement ──
    all_moves = [m for s in sessions for m in s.lateral_moves]
    hosts     = sorted({s.host_id for s in sessions})
    host_tiers: dict = {}
    for s in sessions:
        existing = host_tiers.get(s.host_id)
        if existing is None or s.weighted_score > host_tiers.get(s.host_id + "_score", 0):
            host_tiers[s.host_id]           = s.alert_tier
            host_tiers[s.host_id + "_score"] = s.weighted_score
    nodes = [{"id": h, "tier": host_tiers.get(h, "CLEAN")} for h in hosts]
    edges: list[dict] = []
    seen_edges: set[tuple] = set()
    for move in all_moves:
        key = (move.source_host, move.target_host, move.technique)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({
                "source":    move.source_host,
                "target":    move.target_host,
                "technique": move.technique,
                "mitre_id":  move.mitre_id,
                "evidence":  move.evidence,
                "ts":        move.timestamp.strftime("%H:%M:%S") if move.timestamp else "",
            })

    # ── Timeline ──
    sessions_with_ts  = [s for s in sessions if s.start_time]
    sessions_sorted   = sorted(sessions_with_ts, key=lambda s: s.start_time)
    date_groups: list[dict] = []
    min_label = max_label = ""
    unique_host_count = 0
    heatmap: dict[tuple, dict] = {}
    tier_order = {"P1_INCIDENT": 4, "P2_ALERT": 3, "P3_WARNING": 2, "INFO": 1, "CLEAN": 0}
    for s in sessions_sorted:
        key = (s.start_time.weekday(), s.start_time.hour)
        if key not in heatmap:
            heatmap[key] = {"count": 0, "max_score": 0.0, "max_tier": "CLEAN"}
        heatmap[key]["count"]    += 1
        heatmap[key]["max_score"] = max(heatmap[key]["max_score"], s.weighted_score)
        if tier_order.get(s.alert_tier, 0) > tier_order.get(heatmap[key]["max_tier"], 0):
            heatmap[key]["max_tier"] = s.alert_tier
    heatmap_cells = [{"dow": k[0], "hour": k[1], **v} for k, v in heatmap.items()]
    if sessions_sorted:
        unique_host_count = len({s.host_id for s in sessions_sorted})
        min_label = sessions_sorted[0].start_time.strftime("%Y-%m-%d %H:%M UTC")
        max_label = sessions_sorted[-1].start_time.strftime("%Y-%m-%d %H:%M UTC")
        for day, group_iter in groupby(sessions_sorted, key=lambda s: s.start_time.date()):
            date_groups.append({"label": day.strftime("%A, %B %d %Y"), "sessions": list(group_iter)})

    # ── Executive Summary ──
    has_data = bool(sessions)
    risk_level = risk_color = risk_bg = ""
    tier_counts: Counter = Counter()
    top_sessions: list = []
    mitre_counts: Counter = Counter()
    tactic_breakdown: list[dict] = []
    unique_iocs = unique_hosts = 0
    campaigns: list = []

    if has_data:
        tier_counts  = Counter(s.alert_tier for s in sessions)
        top_sessions = sorted(sessions, key=lambda s: -s.weighted_score)[:5]
        for s in sessions:
            for b in s.blocks:
                for f in b.findings:
                    if f.mitre_id:
                        mitre_counts[f.mitre_id] += 1

        _TACTIC_ORDER_LOCAL = [
            ("Execution",         ["T1059", "T1047", "T1204"]),
            ("Defense Evasion",   ["T1562", "T1140", "T1218", "T1027"]),
            ("Persistence",       ["T1547", "T1546", "T1053", "T1505"]),
            ("Priv. Escalation",  ["T1055", "T1134", "T1068"]),
            ("Cred. Access",      ["T1003", "T1558", "T1555", "T1552"]),
            ("Lateral Movement",  ["T1021", "T1570"]),
            ("Command & Control", ["T1105", "T1197", "T1071", "T1095"]),
        ]
        used_midkeys: set[str] = set()
        for tactic_name, prefixes in _TACTIC_ORDER_LOCAL:
            hits: dict = {}
            for mid, cnt in mitre_counts.items():
                base = mid.split(".")[0]
                if base in prefixes and mid not in used_midkeys:
                    hits[mid] = cnt
                    used_midkeys.add(mid)
            tactic_breakdown.append({"name": tactic_name, "hits": hits,
                                     "active": len(hits) > 0, "total": sum(hits.values())})

        unique_iocs  = len(set(v.strip() for s in sessions for v in s.iocs if v.strip()))
        unique_hosts = len({s.host_id for s in sessions})
        campaigns    = _state.get("campaigns", [])

        if tier_counts.get("P1_INCIDENT", 0) > 0:
            risk_level, risk_color, risk_bg = "CRITICAL", "var(--red)", "var(--red-bg)"
        elif tier_counts.get("P2_ALERT", 0) > 0:
            risk_level, risk_color, risk_bg = "HIGH", "var(--amber)", "var(--amber-bg)"
        elif tier_counts.get("P3_WARNING", 0) > 0:
            risk_level, risk_color, risk_bg = "MEDIUM", "var(--teal)", "var(--teal-bg)"
        else:
            risk_level, risk_color, risk_bg = "LOW", "var(--blue)", "var(--blue-bg)"

    return templates.TemplateResponse(request, "investigation.html", _ctx(request, {
        "page":              "investigation",
        "has_data":          has_data,
        # lateral
        "nodes":             nodes,
        "edges":             edges,
        "all_moves":         all_moves,
        "host_count":        len(hosts),
        "move_count":        len(edges),
        # timeline
        "date_groups":       date_groups,
        "min_label":         min_label,
        "max_label":         max_label,
        "total_sessions":    len(sessions_sorted),
        "unique_host_count": unique_host_count,
        "heatmap_cells":     heatmap_cells,
        # summary
        "risk_level":        risk_level,
        "risk_color":        risk_color,
        "risk_bg":           risk_bg,
        "tier_counts":       tier_counts,
        "top_sessions":      top_sessions,
        "mitre_counts":      dict(sorted(mitre_counts.items(), key=lambda x: -x[1])),
        "tactic_breakdown":  tactic_breakdown,
        "unique_iocs":       unique_iocs,
        "unique_hosts":      unique_hosts,
        "campaigns":         campaigns,
    }))


# ─── Combined page: Export (HTML Report + Navigator + STIX) ───────────────────
@app.get("/export", response_class=HTMLResponse)
async def export_page(request: Request):
    return templates.TemplateResponse(request, "export.html", _ctx(request, {
        "page":     "export",
        "has_data": bool(_state["sessions"]),
    }))


# ─── Analytics fragment (htmx lazy-load for Dashboard Charts tab) ─────────────
@app.get("/analytics/fragment", response_class=HTMLResponse)
async def analytics_fragment(request: Request):
    from reports.iocs import generate_ioc_hub as _gen_ioc
    sessions = _state["sessions"]
    has_data = bool(sessions)

    _empty = {
        "has_data": False, "tier_counts": {}, "all_scores": [],
        "scores_over_time": [], "technique_counts": [], "tactic_rows": [],
        "host_risks": [], "tempo_counts": {}, "ioc_type_counts": {},
        "top_iocs": [], "dur_buckets": [], "dur_labels": [],
        "sigma_pct": 0, "sigma_covered_count": 0, "total_techniques": 0,
        "beacon_count": 0, "unique_iocs": 0,
    }
    if not has_data:
        return templates.TemplateResponse(request, "partials/analytics_frag.html", _ctx(request, _empty))

    tier_counts = dict(Counter(s.alert_tier for s in sessions))
    all_scores  = [round(s.weighted_score, 1) for s in sessions]
    sot = sorted((s for s in sessions if s.start_time), key=lambda s: s.start_time)
    scores_over_time = [{"ts": s.start_time.isoformat(), "score": round(s.weighted_score, 1)} for s in sot]

    tech_ctr: Counter = Counter()
    for s in sessions:
        for t in s.technique_set:
            tech_ctr[t] += 1
    technique_counts = [{"tech": k, "count": v} for k, v in tech_ctr.most_common(12)]

    tactic_hits: dict[str, set] = defaultdict(set)
    tactic_total: dict[str, int] = defaultdict(int)
    for prefix, tac in _TACTIC_FOR.items():
        tactic_total[tac] += 1
    for s in sessions:
        for b in s.blocks:
            for f in b.findings:
                tac = _TACTIC_FOR.get(f.mitre_id[:5])
                if tac:
                    tactic_hits[tac].add(s.session_id)
    tactic_rows = [
        {"name": tac, "count": len(tactic_hits.get(tac, set())),
         "total": tactic_total[tac], "active": tac in tactic_hits}
        for tac in _TACTIC_ORDER
    ]

    host_map: dict[str, dict] = {}
    for s in sessions:
        h = host_map.setdefault(s.host_id, {"host_id": s.host_id, "p1": 0, "p2": 0, "p3": 0, "max_score": 0.0})
        if s.alert_tier == "P1_INCIDENT":  h["p1"] += 1
        elif s.alert_tier == "P2_ALERT":   h["p2"] += 1
        elif s.alert_tier == "P3_WARNING": h["p3"] += 1
        if s.weighted_score > h["max_score"]:
            h["max_score"] = round(s.weighted_score, 1)
    host_risks = sorted(host_map.values(), key=lambda h: -(h["p1"] * 3 + h["p2"] * 2 + h["p3"]))[:12]

    tempo_counts = dict(Counter(
        s.tempo.value if hasattr(s.tempo, "value") else str(s.tempo) for s in sessions
    ))

    ioc_bundle      = _gen_ioc(sessions)
    ioc_type_counts = ioc_bundle.counts()
    unique_iocs     = len(ioc_bundle.entries)
    top_iocs        = [{"value": e.value, "ioc_type": e.ioc_type, "count": e.count}
                       for e in ioc_bundle.entries[:10]]

    dur_labels  = ["0–30s", "30s–2m", "2–10m", "10–30m", "30m+"]
    dur_buckets = [0, 0, 0, 0, 0]
    for s in sessions:
        d = s.duration_seconds
        if d < 30:     dur_buckets[0] += 1
        elif d < 120:  dur_buckets[1] += 1
        elif d < 600:  dur_buckets[2] += 1
        elif d < 1800: dur_buckets[3] += 1
        else:          dur_buckets[4] += 1

    sigma_covered       = set(_SIGMA_TEMPLATES.keys())
    all_techs: set[str] = set()
    for s in sessions:
        all_techs |= s.technique_set
    sigma_covered_count = len(all_techs & sigma_covered)
    total_techniques    = len(all_techs)
    sigma_pct = round(sigma_covered_count / total_techniques * 100, 1) if total_techniques else 0.0
    beacon_count = sum(1 for s in sessions if s.beacon_profile and s.beacon_profile.is_beacon)

    return templates.TemplateResponse(request, "partials/analytics_frag.html", _ctx(request, {
        "has_data":            True,
        "tier_counts":         tier_counts,
        "all_scores":          all_scores,
        "scores_over_time":    scores_over_time,
        "technique_counts":    technique_counts,
        "tactic_rows":         tactic_rows,
        "host_risks":          host_risks,
        "tempo_counts":        tempo_counts,
        "ioc_type_counts":     ioc_type_counts,
        "top_iocs":            top_iocs,
        "dur_buckets":         dur_buckets,
        "dur_labels":          dur_labels,
        "sigma_pct":           sigma_pct,
        "sigma_covered_count": sigma_covered_count,
        "total_techniques":    total_techniques,
        "beacon_count":        beacon_count,
        "unique_iocs":         unique_iocs,
    }))
