"""
ps_classifier — ingest, session stitcher, and scorer

Ingest:   parse Event ID 4104 from EVTX files or JSON (SIEM export)
Stitch:   group ScriptBlocks into Sessions by host + PID + time gap
Score:    compute per-block severity and session weighted score
"""

from __future__ import annotations
import json
import logging
import re
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from core.models import (
    ScriptBlock, Session, TempoClass, ProcessEvent, LogonEvent, shannon_entropy
)
from core.deobfuscator import deobfuscate

log = logging.getLogger(__name__)

SESSION_GAP_SECONDS = 120   # new session if gap between blocks exceeds this
IOC_RE = re.compile(
    r'https?://[^\s\'")\]>]+|'            # URLs
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b|'      # IPv4
    r'\b[0-9a-fA-F]{32,64}\b|'            # MD5/SHA hashes
    r'C:\\[^\s\'")\]>]{5,}',              # Windows paths
    re.IGNORECASE
)


# ── Ingest ────────────────────────────────────────────────────────────────────

def parse_evtx(path: Path) -> Iterator[ScriptBlock]:
    """
    Parse Event ID 4104 records from an EVTX file.
    Requires the 'python-evtx' package (Evtx).
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
        from lxml import etree
    except ImportError:
        raise ImportError(
            "python-evtx and lxml required for EVTX parsing.\n"
            "Install: pip install python-evtx lxml --break-system-packages"
        )

    NS = "http://schemas.microsoft.com/win/2004/08/events/event"

    with evtx.Evtx(str(path)) as log_file:
        for record in log_file.records():
            try:
                root = etree.fromstring(record.xml().encode())
                event_id_el = root.find(f".//{{{NS}}}EventID")
                if event_id_el is None or event_id_el.text != "4104":
                    continue

                def get(tag):
                    el = root.find(f".//{{{NS}}}{tag}")
                    return el.text if el is not None else ""

                def get_data(name):
                    for el in root.findall(f".//{{{NS}}}Data"):
                        if el.get("Name") == name:
                            return el.text or ""
                    return ""

                ts_raw = get("TimeCreated")
                # Parse timestamp — handle both formats
                for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        ts = datetime.strptime(ts_raw[:26], fmt[:len(ts_raw)]).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        ts = datetime.utcnow().replace(tzinfo=timezone.utc)

                raw_text = get_data("ScriptBlockText") or ""
                result   = deobfuscate(raw_text)

                block = ScriptBlock(
                    block_id=get_data("ScriptBlockId") or str(uuid.uuid4()),
                    host_id=get("Computer") or "unknown",
                    process_id=int(get("ProcessID") or 0),
                    thread_id=int(get("ThreadID") or 0),
                    timestamp=ts,
                    path=get_data("Path") or "",
                    raw_text=raw_text,
                    decoded_text=result.decoded,
                    block_number=int(get_data("MessageNumber") or 1),
                    block_total=int(get_data("MessageTotal") or 1),
                    entropy=shannon_entropy(raw_text),
                )
                yield block
            except Exception as exc:
                log.debug("Skipping record: %s", exc)


def parse_evtx_all(path: Path) -> tuple[list[ScriptBlock], list[ProcessEvent], list[LogonEvent]]:
    """
    Parse all relevant event IDs from an EVTX file:
      4104 → ScriptBlock
      4688, Sysmon 1 → ProcessEvent
      4624, 4625, 4648 → LogonEvent
      4698, 4702, 7045 → annotated as ProcessEvent with process_name=schtask/service
    Returns (script_blocks, process_events, logon_events).
    """
    try:
        import Evtx.Evtx as evtx
        from lxml import etree
    except ImportError:
        raise ImportError("python-evtx and lxml required for EVTX parsing.")

    NS = "http://schemas.microsoft.com/win/2004/08/events/event"
    script_blocks: list[ScriptBlock] = []
    process_events: list[ProcessEvent] = []
    logon_events: list[LogonEvent] = []

    _LOGON_TYPES = {0: "Interactive", 2: "Interactive", 3: "Network", 4: "Batch",
                   5: "Service", 7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
                   10: "RemoteInteractive", 11: "CachedInteractive"}

    with evtx.Evtx(str(path)) as log_file:
        for record in log_file.records():
            try:
                root = etree.fromstring(record.xml().encode())

                def get(tag):
                    el = root.find(f".//{{{NS}}}{tag}")
                    return el.text if el is not None else ""

                def get_data(name):
                    for el in root.findall(f".//{{{NS}}}Data"):
                        if el.get("Name") == name:
                            return el.text or ""
                    return ""

                eid_text = get("EventID")
                if not eid_text:
                    continue
                eid = int(eid_text)

                ts_raw = get("TimeCreated")
                ts = datetime.utcnow().replace(tzinfo=timezone.utc)
                for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        ts = datetime.strptime(ts_raw[:26], fmt[:len(ts_raw)]).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        pass

                host = get("Computer") or "unknown"

                if eid == 4104:
                    raw_text = get_data("ScriptBlockText") or ""
                    result = deobfuscate(raw_text)
                    script_blocks.append(ScriptBlock(
                        block_id=get_data("ScriptBlockId") or str(uuid.uuid4()),
                        host_id=host,
                        process_id=int(get("ProcessID") or 0),
                        thread_id=int(get("ThreadID") or 0),
                        timestamp=ts,
                        path=get_data("Path") or "",
                        raw_text=raw_text,
                        decoded_text=result.decoded,
                        block_number=int(get_data("MessageNumber") or 1),
                        block_total=int(get_data("MessageTotal") or 1),
                        entropy=shannon_entropy(raw_text),
                    ))

                elif eid in (4688, 1):  # 1 = Sysmon Process Create
                    cmd = get_data("CommandLine") or get_data("CommandLine") or ""
                    proc_name = get_data("NewProcessName") or get_data("Image") or ""
                    parent_name = get_data("ParentProcessName") or get_data("ParentImage") or ""
                    try:
                        pid = int(get_data("NewProcessId") or get_data("ProcessId") or get("ProcessID") or 0, 16 if "0x" in (get_data("NewProcessId") or "").lower() else 10)
                    except (ValueError, TypeError):
                        pid = 0
                    try:
                        ppid = int(get_data("ProcessId") or get_data("ParentProcessId") or 0, 16 if "0x" in (get_data("ProcessId") or "").lower() else 10)
                    except (ValueError, TypeError):
                        ppid = 0
                    process_events.append(ProcessEvent(
                        event_id=eid,
                        host_id=host,
                        timestamp=ts,
                        process_id=pid,
                        parent_pid=ppid,
                        process_name=proc_name.split("\\")[-1] if proc_name else "",
                        command_line=cmd,
                        parent_name=parent_name.split("\\")[-1] if parent_name else "",
                        user=get_data("SubjectUserName") or get_data("User") or "",
                    ))

                elif eid in (4624, 4625, 4648):
                    try:
                        logon_type = int(get_data("LogonType") or 0)
                    except (ValueError, TypeError):
                        logon_type = 0
                    logon_events.append(LogonEvent(
                        event_id=eid,
                        host_id=host,
                        timestamp=ts,
                        target_host=get_data("WorkstationName") or get_data("TargetServerName") or host,
                        username=get_data("TargetUserName") or get_data("SubjectUserName") or "",
                        logon_type=logon_type,
                        source_ip=get_data("IpAddress") or "",
                        logon_id=get_data("TargetLogonId") or "",
                        success=(eid != 4625),
                    ))

                elif eid in (4698, 4702):  # Schtask created/modified
                    process_events.append(ProcessEvent(
                        event_id=eid,
                        host_id=host,
                        timestamp=ts,
                        process_id=0,
                        parent_pid=0,
                        process_name="schtasks.exe",
                        command_line=get_data("TaskContent") or get_data("TaskName") or "",
                        parent_name="",
                        user=get_data("SubjectUserName") or "",
                    ))

                elif eid == 7045:  # New service installed
                    process_events.append(ProcessEvent(
                        event_id=eid,
                        host_id=host,
                        timestamp=ts,
                        process_id=0,
                        parent_pid=0,
                        process_name=get_data("ServiceName") or "unknown_service",
                        command_line=get_data("ImagePath") or "",
                        parent_name="services.exe",
                        user=get_data("AccountName") or "",
                    ))

            except Exception as exc:
                log.debug("Skipping record: %s", exc)

    return script_blocks, process_events, logon_events


def parse_json_export(path: Path) -> Iterator[ScriptBlock]:
    """
    Parse SIEM JSON export. Expected format: array of objects with keys
    matching ScriptBlock fields, or a flat Splunk/Elastic export with
    standard Windows event fields.
    """
    with path.open() as f:
        data = json.load(f)

    if isinstance(data, dict):
        data = data.get("hits", data.get("events", data.get("results", [data])))

    for record in data:
        # Handle nested Splunk/Elastic _source
        r = record.get("_source", record)

        raw_text = (
            r.get("ScriptBlockText") or
            r.get("script_block_text") or
            r.get("Message") or ""
        )
        if not raw_text:
            continue

        result = deobfuscate(raw_text)

        ts_raw = r.get("@timestamp") or r.get("TimeCreated") or r.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.utcnow().replace(tzinfo=timezone.utc)

        yield ScriptBlock(
            block_id=r.get("ScriptBlockId") or str(uuid.uuid4()),
            host_id=r.get("Computer") or r.get("host") or r.get("hostname", "unknown"),
            process_id=int(r.get("ProcessId") or r.get("process_id") or 0),
            thread_id=int(r.get("ThreadId") or r.get("thread_id") or 0),
            timestamp=ts,
            path=r.get("Path") or r.get("script_path") or "",
            raw_text=raw_text,
            decoded_text=result.decoded,
            block_number=int(r.get("MessageNumber") or 1),
            block_total=int(r.get("MessageTotal") or 1),
            entropy=shannon_entropy(raw_text),
        )


def reassemble_multipart(blocks: list[ScriptBlock]) -> list[ScriptBlock]:
    """
    Reassemble multi-part script blocks (MessageNumber > 1) sharing a ScriptBlockId.
    Returns a new list with complete single-part blocks.
    """
    groups: dict[str, list[ScriptBlock]] = defaultdict(list)
    singles = []

    for b in blocks:
        if b.block_total > 1:
            groups[b.block_id].append(b)
        else:
            singles.append(b)

    for block_id, parts in groups.items():
        parts.sort(key=lambda b: b.block_number)
        if len(parts) == parts[0].block_total:
            # All parts present — merge
            merged_raw     = "".join(p.raw_text for p in parts)
            merged_decoded = "".join(p.decoded_text for p in parts)
            base           = parts[0]
            singles.append(ScriptBlock(
                block_id=block_id,
                host_id=base.host_id,
                process_id=base.process_id,
                thread_id=base.thread_id,
                timestamp=base.timestamp,
                path=base.path,
                raw_text=merged_raw,
                decoded_text=merged_decoded,
                block_number=1,
                block_total=1,
                entropy=shannon_entropy(merged_raw),
            ))
        else:
            # Incomplete — add parts individually (partial analysis)
            log.warning("Incomplete multi-part block %s (%d/%d parts)",
                        block_id, len(parts), parts[0].block_total)
            singles.extend(parts)

    return sorted(singles, key=lambda b: (b.host_id, b.process_id, b.timestamp))


# ── Session stitcher ──────────────────────────────────────────────────────────

def stitch_sessions(blocks: list[ScriptBlock],
                    gap_seconds: int = SESSION_GAP_SECONDS) -> list[Session]:
    """
    Group ScriptBlocks into Sessions by (host_id, process_id) with a time-gap boundary.
    """
    sorted_blocks = sorted(blocks, key=lambda b: (b.host_id, b.process_id, b.timestamp))
    sessions: list[Session] = []
    current:  list[ScriptBlock] = []

    def _flush(buf: list[ScriptBlock]) -> Session:
        sid = f"{buf[0].host_id}_{buf[0].process_id}_{buf[0].timestamp.strftime('%Y%m%dT%H%M%S')}"
        return Session(
            session_id=sid,
            host_id=buf[0].host_id,
            process_id=buf[0].process_id,
            blocks=list(buf),
            start_time=buf[0].timestamp,
            end_time=buf[-1].timestamp,
        )

    for block in sorted_blocks:
        if not current:
            current.append(block)
            continue

        prev = current[-1]
        same_host = (prev.host_id == block.host_id)
        same_pid  = (prev.process_id == block.process_id)
        gap       = (block.timestamp - prev.timestamp).total_seconds()
        within_gap = gap <= gap_seconds

        if same_host and same_pid and within_gap:
            current.append(block)
        else:
            sessions.append(_flush(current))
            current = [block]

    if current:
        sessions.append(_flush(current))

    return sessions


# ── Tempo classifier ──────────────────────────────────────────────────────────

def classify_tempo(session: Session) -> TempoClass:
    """
    Classify attacker operating tempo from inter-block timing.
    Human operators: slow + high variance. Automated: fast + low variance.
    """
    if len(session.blocks) < 2:
        return TempoClass.SINGLE_BLOCK

    gaps = [
        (session.blocks[i + 1].timestamp - session.blocks[i].timestamp).total_seconds()
        for i in range(len(session.blocks) - 1)
    ]
    gaps = [max(g, 0.001) for g in gaps]   # floor to avoid division by zero

    mean_gap = statistics.mean(gaps)
    try:
        stdev    = statistics.stdev(gaps)
        cv       = stdev / mean_gap        # coefficient of variation
    except statistics.StatisticsError:
        cv = 0.0

    if mean_gap < 0.5 and cv < 0.3:
        return TempoClass.AUTOMATED_STAGER
    if mean_gap > 2.0 and cv > 0.8:
        return TempoClass.INTERACTIVE_OPERATOR
    return TempoClass.MIXED


# ── IOC extractor ─────────────────────────────────────────────────────────────

def extract_iocs(text: str) -> list[str]:
    """Extract URLs, IPs, hashes, and file paths from decoded PS text."""
    return list(set(IOC_RE.findall(text)))


# ── Scorer ────────────────────────────────────────────────────────────────────

def score_block(block: ScriptBlock) -> int:
    """Compute 0–100 severity for a single ScriptBlock."""
    if not block.findings:
        # Entropy-only: no rule fired but block looks encoded
        if block.entropy > 6.0 and len(block.decoded_text) > 500:
            return 40
        return 0

    base = max(f.severity for f in block.findings)

    # Combination bonus: multiple distinct techniques = attack is progressing
    distinct = len({f.technique_id for f in block.findings})
    combo_bonus = min(15, (distinct - 1) * 8)

    # Entropy bonus: rule fired AND block is heavily encoded
    entropy_bonus = 10 if block.entropy > 5.5 else 0

    return min(100, base + combo_bonus + entropy_bonus)


def score_session(session: Session) -> float:
    """
    Compute 0–100 weighted session score.
    Considers: max block score, weighted average, TTP chain bonuses, tempo.
    """
    scores = [b.severity for b in session.blocks if b.severity > 0]
    if not scores:
        return 0.0

    max_score    = max(scores)
    top3         = sorted(scores, reverse=True)[:3]
    weighted_avg = sum(top3) * 0.7 + (sum(scores) / len(scores)) * 0.3

    # TTP chain bonuses — recognised kill-chain progressions
    techs = session.technique_set
    chain_bonus = 0

    if {"AMSI_BYPASS_REFLECT", "DOWNLOAD_CRADLE_WC"}.issubset(techs):
        chain_bonus += 15
    if "AMSI_BYPASS_REFLECT" in techs and "AMSI_BYPASS_COM" in techs:
        chain_bonus += 8   # double-bypass = determined operator
    if "REFLECTIVE_INJECT" in techs or "SHELLCODE_MARSHAL" in techs:
        chain_bonus += 20
    if "COBALT_STRIKE" in techs:
        chain_bonus += 20
    if "REVERSE_SHELL" in techs and "DOWNLOAD_CRADLE_WC" in techs:
        chain_bonus += 15
    # Credential-access kill chain: bypass + cred dump
    cred_techs = {"CRED_HARVEST", "DCSYNC_PATTERN", "LSASS_READ", "SAM_DUMP", "KERBEROAST_SPN"}
    if techs & cred_techs and techs & {"AMSI_BYPASS_REFLECT", "AMSI_BYPASS_PATCH", "ETW_PATCH_INLINE"}:
        chain_bonus += 15
    # Full attack chain: download → execute → lateral
    lateral_techs = {"LATERAL_PSREMOTING", "LATERAL_WMI_EXEC", "LATERAL_INVOKE_CMD"}
    if techs & lateral_techs and techs & {"DOWNLOAD_CRADLE_WC", "DOWNLOAD_CRADLE_IWR"}:
        chain_bonus += 20
    # LOLBin cluster: 2+ LOLBins = intentional chaining
    lolbin_techs = {"LOLBIN_CERTUTIL", "LOLBIN_MSHTA", "LOLBIN_REGSVR32", "LOLBIN_RUNDLL32", "LOLBIN_BITSADMIN"}
    if len(techs & lolbin_techs) >= 2:
        chain_bonus += 12

    # Tempo bonus: interactive human is more dangerous than automated script
    tempo_bonus = 10 if session.tempo == TempoClass.INTERACTIVE_OPERATOR else 0

    return min(100.0, max_score * 0.4 + weighted_avg * 0.6 + chain_bonus + tempo_bonus)


def enrich_session(session: Session, run_beacon: bool = True) -> Session:
    """
    After classification: score blocks, score session, extract IOCs, classify tempo.
    Call this after Classifier.classify_batch() has populated block.findings.
    """
    # Score each block
    for block in session.blocks:
        block.severity = score_block(block)

    # Aggregate technique set
    session.technique_set = {
        f.technique_id
        for b in session.blocks
        for f in b.findings
    }

    # Classify tempo
    session.tempo = classify_tempo(session)

    # Session score
    session.weighted_score = score_session(session)
    session.max_severity   = max((b.severity for b in session.blocks), default=0)

    # Extract IOCs from all decoded text
    all_text = "\n".join(b.decoded_text for b in session.blocks)
    session.iocs = extract_iocs(all_text)

    # Deobfuscation pass count
    session.deobfuscation_passes = sum(
        1 for b in session.blocks if b.decoded_text != b.raw_text
    )

    # Beacon detection
    if run_beacon and len(session.blocks) >= 6:
        try:
            from core.beacon import detect_beacon
            session.beacon_profile = detect_beacon(session)
        except Exception as exc:
            log.debug("Beacon detection failed: %s", exc)

    return session
