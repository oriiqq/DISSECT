"""
ps_classifier — STIX 2.1 Bundle export

Serialises analysis results as a STIX 2.1 Bundle containing:
  - identity (tool identity)
  - malware objects (per campaign / technique cluster)
  - indicators (IOCs as STIX pattern indicators)
  - attack-pattern objects (MITRE ATT&CK techniques)
  - relationship objects linking indicators → malware → attack-patterns
  - note objects (session summaries)
"""

from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from core.models import Session

STIX_VERSION = "2.1"
TOOL_NAME = "ps_classifier"
TOOL_VERSION = "1.0"

_MITRE_URL = "https://attack.mitre.org/techniques/"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sid(prefix: str, seed: str) -> str:
    """Deterministic STIX ID from a seed string."""
    h = hashlib.sha256(seed.encode()).hexdigest()[:32]
    return f"{prefix}--{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _identity() -> dict:
    return {
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": _sid("identity", TOOL_NAME),
        "created": _now(),
        "modified": _now(),
        "name": TOOL_NAME,
        "identity_class": "system",
        "description": f"PowerShell Script Block Classifier v{TOOL_VERSION}",
    }


def _attack_pattern(mitre_id: str, name: str) -> dict:
    return {
        "type": "attack-pattern",
        "spec_version": STIX_VERSION,
        "id": _sid("attack-pattern", mitre_id),
        "created": _now(),
        "modified": _now(),
        "name": f"MITRE ATT&CK {mitre_id}: {name}",
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": mitre_id,
            "url": f"{_MITRE_URL}{mitre_id.replace('.', '/')}",
        }],
    }


def _ioc_to_stix_pattern(ioc: str) -> str | None:
    """Convert an IOC string to a STIX 2.1 pattern expression."""
    ioc = ioc.strip()
    if ioc.startswith("http://") or ioc.startswith("https://"):
        escaped = ioc.replace("'", "\\'")
        return f"[url:value = '{escaped}']"
    import re
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', ioc):
        return f"[ipv4-addr:value = '{ioc}']"
    if re.match(r'^[0-9a-fA-F]{64}$', ioc):
        return f"[file:hashes.SHA-256 = '{ioc.lower()}']"
    if re.match(r'^[0-9a-fA-F]{32}$', ioc):
        return f"[file:hashes.MD5 = '{ioc.lower()}']"
    if ioc.startswith("C:\\") or ioc.startswith("c:\\"):
        escaped = ioc.replace("\\", "\\\\").replace("'", "\\'")
        return f"[file:name = '{escaped}']"
    return None


def _indicator(ioc: str, created_by_id: str, mitre_refs: list[str]) -> dict | None:
    pattern = _ioc_to_stix_pattern(ioc)
    if not pattern:
        return None
    now = _now()
    return {
        "type": "indicator",
        "spec_version": STIX_VERSION,
        "id": _sid("indicator", ioc),
        "created": now,
        "modified": now,
        "created_by_ref": created_by_id,
        "name": ioc[:120],
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
    }


def _relationship(source_id: str, rel_type: str, target_id: str, created_by_id: str) -> dict:
    now = _now()
    return {
        "type": "relationship",
        "spec_version": STIX_VERSION,
        "id": _sid("relationship", f"{source_id}-{rel_type}-{target_id}"),
        "created": now,
        "modified": now,
        "created_by_ref": created_by_id,
        "relationship_type": rel_type,
        "source_ref": source_id,
        "target_ref": target_id,
    }


def _malware_obj(session: Session, created_by_id: str) -> dict:
    now = _now()
    name = f"ps_classifier Session {session.session_id}"
    return {
        "type": "malware",
        "spec_version": STIX_VERSION,
        "id": _sid("malware", session.session_id),
        "created": now,
        "modified": now,
        "created_by_ref": created_by_id,
        "name": name,
        "malware_types": ["trojan"],
        "is_family": False,
        "description": (
            f"Tier: {session.alert_tier} | "
            f"Score: {session.weighted_score:.0f}/100 | "
            f"Host: {session.host_id} | "
            f"Techniques: {', '.join(sorted(session.technique_set))}"
        ),
    }


def _note_obj(session: Session, malware_id: str, created_by_id: str) -> dict:
    now = _now()
    content = (
        f"Session ID: {session.session_id}\n"
        f"Host: {session.host_id}\n"
        f"Alert Tier: {session.alert_tier}\n"
        f"Score: {session.weighted_score:.1f}/100\n"
        f"Blocks: {len(session.blocks)}\n"
        f"IOC count: {len(session.iocs)}\n"
        f"Techniques: {', '.join(sorted(session.technique_set)) or 'none'}\n"
    )
    if session.beacon_profile and session.beacon_profile.is_beacon:
        bp = session.beacon_profile
        content += f"Beacon: period={bp.period_seconds}s jitter={bp.jitter_pct:.1%} conf={bp.confidence:.0%}\n"
    return {
        "type": "note",
        "spec_version": STIX_VERSION,
        "id": _sid("note", session.session_id + "-note"),
        "created": now,
        "modified": now,
        "created_by_ref": created_by_id,
        "content": content,
        "object_refs": [malware_id],
    }


def generate_stix_bundle(sessions: list[Session]) -> str:
    """
    Build a STIX 2.1 JSON Bundle from a list of Sessions.
    Returns the serialised JSON string.
    """
    identity = _identity()
    created_by_id = identity["id"]
    objects: list[dict] = [identity]

    seen_attack_patterns: dict[str, dict] = {}
    seen_indicators: dict[str, dict] = {}

    # Collect all unique MITRE technique → attack-pattern objects
    mitre_map: dict[str, str] = {}  # mitre_id → STIX id
    for session in sessions:
        for block in session.blocks:
            for finding in block.findings:
                mid = finding.mitre_id
                if mid and mid not in seen_attack_patterns:
                    ap = _attack_pattern(mid, finding.technique_id)
                    seen_attack_patterns[mid] = ap
                    mitre_map[mid] = ap["id"]

    objects.extend(seen_attack_patterns.values())

    for session in sessions:
        if session.alert_tier == "CLEAN":
            continue

        mal = _malware_obj(session, created_by_id)
        objects.append(mal)
        objects.append(_note_obj(session, mal["id"], created_by_id))

        # Link malware → attack-patterns
        session_mitre = {f.mitre_id for b in session.blocks for f in b.findings if f.mitre_id}
        for mid in session_mitre:
            if mid in mitre_map:
                objects.append(_relationship(mal["id"], "uses", mitre_map[mid], created_by_id))

        # IOC indicators
        for ioc in session.iocs[:30]:
            if ioc not in seen_indicators:
                ind = _indicator(ioc, created_by_id, [])
                if ind:
                    seen_indicators[ioc] = ind
                    objects.append(ind)
            if ioc in seen_indicators:
                objects.append(_relationship(
                    seen_indicators[ioc]["id"], "indicates", mal["id"], created_by_id
                ))

        # TI hit malware names → additional malware objects
        for ti in session.ti_hits:
            if ti.malware_name:
                ti_mal_id = _sid("malware", ti.malware_name + "-known")
                ti_mal = {
                    "type": "malware",
                    "spec_version": STIX_VERSION,
                    "id": ti_mal_id,
                    "created": _now(),
                    "modified": _now(),
                    "name": ti.malware_name,
                    "malware_types": ["trojan"],
                    "is_family": True,
                    "description": f"Source: {ti.source} | Tags: {', '.join(ti.tags)}",
                }
                if ti_mal_id not in {o["id"] for o in objects if o.get("type") == "malware"}:
                    objects.append(ti_mal)
                objects.append(_relationship(mal["id"], "variant-of", ti_mal_id, created_by_id))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)
