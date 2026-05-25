#!/usr/bin/env python3
"""
ps_classifier — CLI entry point

Usage examples:
  python psc.py analyse --input security.evtx --report report.html
  python psc.py analyse --input events.json --baseline baseline.json --report out.html
  python psc.py baseline --input clean_logs.json --save baseline.json
  python psc.py analyse --input security.evtx --json-out results.json
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path

# ── Ensure project root is on sys.path ────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from core.models       import Session
from core.ingest       import (parse_evtx, parse_json_export,
                                reassemble_multipart, stitch_sessions, enrich_session)
from core.classifier   import Classifier
from core.fingerprinter import cluster_into_campaigns
from core.baseline     import EnvironmentBaseline
from reports.html_report import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("psc")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_blocks(input_path: Path):
    suffix = input_path.suffix.lower()
    if suffix == ".evtx":
        log.info("Parsing EVTX: %s", input_path)
        return list(parse_evtx(input_path))
    elif suffix in (".json", ".ndjson", ".jsonl"):
        log.info("Parsing JSON export: %s", input_path)
        return list(parse_json_export(input_path))
    else:
        raise ValueError(f"Unsupported input format: {suffix}  (expected .evtx or .json)")


def _sessions_to_dict(sessions: list[Session]) -> list[dict]:
    """Serialize sessions to JSON-serialisable dicts."""
    out = []
    for s in sessions:
        out.append({
            "session_id":     s.session_id,
            "host_id":        s.host_id,
            "process_id":     s.process_id,
            "alert_tier":     s.alert_tier,
            "weighted_score": round(s.weighted_score, 1),
            "max_severity":   s.max_severity,
            "tempo":          s.tempo.value,
            "technique_set":  sorted(s.technique_set),
            "iocs":           s.iocs,
            "block_count":    len(s.blocks),
            "campaign_id":    s.campaign_id,
            "start_time":     s.start_time.isoformat() if s.start_time else None,
            "end_time":       s.end_time.isoformat()   if s.end_time   else None,
        })
    return out


# ── Sub-commands ──────────────────────────────────────────────────────────────

def cmd_analyse(args):
    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)

    # ── 1. Ingest ──────────────────────────────────────────────────────────
    raw_blocks = _load_blocks(input_path)
    log.info("Loaded %d raw script blocks", len(raw_blocks))

    # ── 2. Reassemble multi-part blocks ───────────────────────────────────
    blocks = reassemble_multipart(raw_blocks)
    log.info("After reassembly: %d blocks", len(blocks))

    # ── 3. Classify (deobfuscate → rule-match) ────────────────────────────
    classifier = Classifier()
    blocks = classifier.classify_batch(blocks)

    # ── 4. Load optional baseline ──────────────────────────────────────────
    baseline = None
    if args.baseline and Path(args.baseline).exists():
        baseline = EnvironmentBaseline.load(args.baseline)
        log.info("Baseline loaded: %s", baseline.summary())

    # ── 5. Stitch sessions ─────────────────────────────────────────────────
    sessions = stitch_sessions(blocks, gap_seconds=args.session_gap)
    log.info("Stitched into %d sessions", len(sessions))

    # ── 6. Enrich: score + tempo + IOCs ──────────────────────────────────
    for session in sessions:
        enrich_session(session)
        if baseline:
            all_text = "\n".join(b.decoded_text for b in session.blocks)
            session.baseline_anomaly = baseline.anomaly_score(session.blocks[0]) if session.blocks else 0.0

    # ── 7. Cross-host campaign correlation ────────────────────────────────
    campaigns = cluster_into_campaigns(sessions)
    if campaigns:
        confirmed = sum(1 for c in campaigns if c.is_confirmed)
        log.info("Found %d campaigns (%d confirmed)", len(campaigns), confirmed)

    # ── 8. Summary to stdout ──────────────────────────────────────────────
    p1 = sum(1 for s in sessions if s.alert_tier == "P1_INCIDENT")
    p2 = sum(1 for s in sessions if s.alert_tier == "P2_ALERT")
    p3 = sum(1 for s in sessions if s.alert_tier == "P3_WARNING")

    print(f"\n{'─'*50}")
    print(f"  ps_classifier results")
    print(f"{'─'*50}")
    print(f"  Sessions total : {len(sessions)}")
    print(f"  P1 Incidents   : {p1}")
    print(f"  P2 Alerts      : {p2}")
    print(f"  P3 Warnings    : {p3}")
    print(f"  Campaigns      : {len(campaigns)}")
    print(f"{'─'*50}\n")

    if p1 + p2 > 0:
        print("  Top sessions:")
        top = sorted(sessions, key=lambda s: -s.weighted_score)[:5]
        for s in top:
            if s.alert_tier in ("P1_INCIDENT", "P2_ALERT"):
                print(f"    [{s.alert_tier:12s}] {s.host_id:30s} score={s.weighted_score:.0f}  "
                      f"tempo={s.tempo.value}  techs={','.join(sorted(s.technique_set))[:60]}")
        print()

    # ── 9. Output ──────────────────────────────────────────────────────────
    if args.report:
        report_path = save_report(sessions, args.report, campaigns=campaigns)
        log.info("HTML report written: %s", report_path)
        print(f"  Report: {report_path}")

    if args.sigma_out:
        from reports.sigma import save_sigma_bundle
        written = save_sigma_bundle(sessions, args.sigma_out)
        log.info("Sigma rules written: %d files to %s", len(written), args.sigma_out)
        print(f"  Sigma rules: {len(written)} files in {args.sigma_out}")

    if args.json_out:
        out = {
            "sessions":  _sessions_to_dict(sessions),
            "campaigns": [
                {
                    "campaign_id":    c.campaign_id,
                    "fingerprint":    c.fingerprint_hash,
                    "confirmed":      c.is_confirmed,
                    "host_count":     len(c.host_ids),
                    "session_count":  len(c.sessions),
                    "peak_severity":  c.peak_severity,
                    "hosts":          sorted(c.host_ids),
                }
                for c in campaigns
            ],
        }
        Path(args.json_out).write_text(json.dumps(out, indent=2))
        log.info("JSON output written: %s", args.json_out)


def cmd_baseline(args):
    """Build or extend an environment baseline from known-good logs."""
    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input not found: %s", input_path)
        sys.exit(1)

    # Load existing baseline or start fresh
    if args.save and Path(args.save).exists():
        baseline = EnvironmentBaseline.load(args.save)
        log.info("Extending existing baseline")
    else:
        baseline = EnvironmentBaseline()
        log.info("Building new baseline")

    blocks = reassemble_multipart(_load_blocks(input_path))
    baseline.ingest_batch(blocks)
    log.info("Baseline now contains %d observations", baseline.observation_count)

    if args.save:
        baseline.save(args.save)
        print(f"\n  Baseline saved: {args.save}")
        print(f"  Observations:  {baseline.observation_count}")
        print(f"  Unique cmdlets:{len(baseline.cmdlet_frequency)}")
    else:
        print(json.dumps(baseline.summary(), indent=2))


def cmd_serve(args):
    """Start the FastAPI + htmx web dashboard."""
    try:
        import uvicorn
    except ImportError:
        log.error("uvicorn not installed. Run: pip install uvicorn")
        sys.exit(1)
    print("\n  ps_classifier web dashboard")
    print(f"  http://{args.host}:{args.port}\n")
    uvicorn.run(
        "web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


# ── Argument parser ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="psc",
        description="ps_classifier — PowerShell transcript anomaly classifier",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # analyse
    p_analyse = sub.add_parser("analyse", help="Classify PS transcripts and produce a report")
    p_analyse.add_argument("--input",       required=True,  help=".evtx or .json file")
    p_analyse.add_argument("--report",                      help="Write HTML report to this path")
    p_analyse.add_argument("--json-out",                    help="Write JSON results to this path")
    p_analyse.add_argument("--sigma-out",                   help="Directory to write Sigma rule .yml files")
    p_analyse.add_argument("--baseline",                    help="Path to baseline.json for FP suppression")
    p_analyse.add_argument("--session-gap", type=int, default=120,
                           help="Session boundary gap in seconds (default: 120)")

    # baseline
    p_baseline = sub.add_parser("baseline", help="Build or extend an environment baseline")
    p_baseline.add_argument("--input",  required=True, help=".evtx or .json of known-good logs")
    p_baseline.add_argument("--save",                  help="Path to save/update baseline.json")

    p_serve = sub.add_parser("serve", help="Start the web dashboard (FastAPI + htmx)")
    p_serve.add_argument("--host",   default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_serve.add_argument("--port",   type=int, default=8000, help="Port (default: 8000)")
    p_serve.add_argument("--reload", action="store_true", help="Enable auto-reload (dev mode)")

    args = parser.parse_args()

    if args.command == "analyse":
        cmd_analyse(args)
    elif args.command == "baseline":
        cmd_baseline(args)
    elif args.command == "serve":
        cmd_serve(args)


if __name__ == "__main__":
    main()
