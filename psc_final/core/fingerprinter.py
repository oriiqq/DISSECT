"""
ps_classifier — cross-host fingerprinter & campaign correlator

Our key differentiator: clusters sessions across hosts by obfuscation style.
Same operator → same fingerprint → same campaign, even with different payloads.
"""

from __future__ import annotations
import re
import uuid
import logging
from collections import defaultdict
from datetime import datetime

from core.models import ObfuscationFingerprint, Session, Campaign

log = logging.getLogger(__name__)


# ── Feature extractors ────────────────────────────────────────────────────────

def _extract_base64_chunk_sizes(text: str) -> tuple:
    """Detect base64 block lengths — reveals line-wrap style of the encoder."""
    blobs = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', text)
    return tuple(sorted({len(b) for b in blobs}))


def _extract_char_code_offsets(text: str) -> frozenset:
    """Collect all integer values used in [char]N patterns — reveals XOR key choices."""
    vals = re.findall(r'\[char\]\s*(\d+)', text, re.IGNORECASE)
    return frozenset(int(v) for v in vals if int(v) > 31)


def _extract_iex_nesting_depth(text: str) -> int:
    """Count maximum IEX nesting depth: IEX(IEX(IEX(...)))."""
    depth = 0
    max_depth = 0
    for ch in text:
        if ch == '(':
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == ')':
            depth = max(0, depth - 1)
    iex_count = len(re.findall(r'\bIEX\b|\bInvoke-Expression\b', text, re.IGNORECASE))
    return min(iex_count, max_depth)


def _extract_string_join_style(text: str) -> str | None:
    """Which string-join idiom does this operator prefer?"""
    if re.search(r'-join\s*[\'"]', text, re.IGNORECASE):
        return "-join"
    if re.search(r'\[string\]::Join', text, re.IGNORECASE):
        return "[string]::Join"
    if re.search(r'\+\s*[\'"]', text):
        return "concat"
    return None


def _extract_backtick_density(text: str) -> float:
    """Backticks per 100 characters — reveals how heavily the operator uses them."""
    if not text:
        return 0.0
    return (text.count('`') / len(text)) * 100


def _extract_format_string_slots(text: str) -> int:
    """Maximum {N} slot count in any format string — reveals formatting habits."""
    matches = re.findall(r'["\'](\{[\d\s,:-]+\}(?:\s*\{[\d\s,:-]+\})*)["\']', text)
    if not matches:
        return 0
    return max(len(re.findall(r'\{\d+\}', m)) for m in matches)


# ── Public API ────────────────────────────────────────────────────────────────

def extract_fingerprint(session: Session) -> ObfuscationFingerprint:
    """
    Build an ObfuscationFingerprint from all decoded text in the session.
    The fingerprint captures the *style* of obfuscation, not the payload.
    """
    all_raw  = "\n".join(b.raw_text     for b in session.blocks)
    all_dec  = "\n".join(b.decoded_text for b in session.blocks)

    return ObfuscationFingerprint(
        base64_chunk_sizes=_extract_base64_chunk_sizes(all_raw),
        char_code_offsets=_extract_char_code_offsets(all_raw),
        iex_nesting_depth=_extract_iex_nesting_depth(all_raw),
        string_join_style=_extract_string_join_style(all_raw),
        backtick_density=_extract_backtick_density(all_raw),
        format_string_slots=_extract_format_string_slots(all_raw),
    )


def cluster_into_campaigns(sessions: list[Session],
                            min_hosts: int = 2,
                            min_sessions: int = 3) -> list[Campaign]:
    """
    Group sessions by fingerprint hash. Clusters meeting min_hosts + min_sessions
    thresholds are promoted to confirmed Campaigns.

    Args:
        sessions:     enriched Session objects (post-score)
        min_hosts:    minimum distinct hosts to confirm a campaign
        min_sessions: minimum sessions to confirm a campaign

    Returns:
        List of Campaign objects (confirmed and tentative)
    """
    # Only fingerprint sessions with meaningful findings
    active_sessions = [s for s in sessions if s.weighted_score > 20]

    # Attach fingerprints
    fp_map: dict[str, list[Session]] = defaultdict(list)
    for session in active_sessions:
        fp = extract_fingerprint(session)
        session.fingerprint = fp
        fp_map[fp.fingerprint_hash()].append(session)

    campaigns: list[Campaign] = []
    for fp_hash, sess_group in fp_map.items():
        host_ids  = {s.host_id for s in sess_group}
        campaign_id = str(uuid.uuid4())[:8]

        # Tag each session with this campaign
        for s in sess_group:
            s.campaign_id = campaign_id

        timestamps = [s.start_time for s in sess_group if s.start_time]
        campaign = Campaign(
            campaign_id=campaign_id,
            fingerprint_hash=fp_hash,
            sessions=sess_group,
            host_ids=host_ids,
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
            peak_severity=max(s.max_severity for s in sess_group),
        )
        campaigns.append(campaign)

        status = "CONFIRMED" if campaign.is_confirmed else "tentative"
        log.info(
            "Campaign %s [%s]: %d sessions across %d hosts, peak severity %d",
            campaign_id, status, len(sess_group), len(host_ids), campaign.peak_severity
        )

    # Sort: confirmed campaigns first, then by peak severity
    return sorted(campaigns, key=lambda c: (not c.is_confirmed, -c.peak_severity))
