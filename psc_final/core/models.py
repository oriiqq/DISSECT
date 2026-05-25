"""
ps_classifier — core data models
All pipeline stages operate on these structures.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import hashlib
import math
from collections import Counter


# ── Enums ────────────────────────────────────────────────────────────────────

class Severity(int, Enum):
    INFO     = 10
    LOW      = 25
    MEDIUM   = 50
    HIGH     = 75
    CRITICAL = 90

class TempoClass(str, Enum):
    SINGLE_BLOCK        = "single_block"
    AUTOMATED_STAGER    = "automated_stager"
    INTERACTIVE_OPERATOR = "interactive_operator"
    LATERAL_SWEEP       = "lateral_sweep"
    MIXED               = "mixed"

class RuleHealth(str, Enum):
    HIGH_VALUE = "high_value"
    NOMINAL    = "nominal"
    NOISY      = "noisy"
    STALE      = "stale"


# ── Leaf objects ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """One detected technique within a single ScriptBlock."""
    technique_id:  str           # e.g. "AMSI_BYPASS_REFLECT"
    mitre_id:      str           # e.g. "T1562.001"
    severity:      int           # 0–100
    rule_name:     str
    matched_text:  str           # the exact substring that triggered the rule
    context:       str           # 80-char window around match
    confidence:    float = 1.0   # 0–1; reduced for heuristic/entropy-only matches


@dataclass
class ObfuscationFingerprint:
    """
    Style features that remain stable across payloads from the same operator.
    Used for cross-host campaign correlation.
    """
    base64_chunk_sizes:  tuple        # padding/line-length pattern
    char_code_offsets:   frozenset    # XOR keys / rotation values observed
    iex_nesting_depth:   int          # max depth of IEX(IEX(...)) wrapping
    string_join_style:   str | None   # '-join', '[string]::Join', '+', None
    backtick_density:    float        # backticks per 100 chars
    format_string_slots: int          # "{0}{2}{1}" max slot count seen

    def fingerprint_hash(self) -> str:
        """Stable 16-char hex hash — same operator → same hash across payloads."""
        data = (
            self.char_code_offsets,
            self.iex_nesting_depth,
            self.string_join_style,
            round(self.backtick_density, 1),
            self.format_string_slots,
        )
        return hashlib.sha256(str(data).encode()).hexdigest()[:16]


# ── Primary pipeline objects ──────────────────────────────────────────────────

@dataclass
class ScriptBlock:
    """
    One Event ID 4104 record, fully parsed and enriched.
    Multi-part blocks (MessageNumber > 1) are reassembled before this stage.
    """
    block_id:      str           # GUID from EventData.ScriptBlockId
    host_id:       str           # hostname or sensor ID
    process_id:    int
    thread_id:     int
    timestamp:     datetime
    path:          str           # ScriptBlockFile — empty if interactive
    raw_text:      str           # original ScriptBlockText (forensic fidelity)
    decoded_text:  str           # after deobfuscation passes
    block_number:  int = 1       # MessageNumber
    block_total:   int = 1       # MessageTotal
    entropy:       float = 0.0   # Shannon entropy of raw_text
    findings:      list[Finding] = field(default_factory=list)
    severity:      int = 0       # computed by scorer after classification

    def block_hash(self) -> str:
        """Stable hash of decoded content — for baseline deduplication."""
        return hashlib.sha256(self.decoded_text.encode()).hexdigest()[:20]

    def is_complete(self) -> bool:
        return self.block_number == self.block_total


@dataclass
class Session:
    """
    A stitched sequence of ScriptBlocks sharing the same host + PID + time window.
    This is the primary unit of analysis and alerting.
    """
    session_id:       str
    host_id:          str
    process_id:       int
    blocks:           list[ScriptBlock] = field(default_factory=list)
    start_time:       Optional[datetime] = None
    end_time:         Optional[datetime] = None
    max_severity:     int = 0
    weighted_score:   float = 0.0
    technique_set:    set[str] = field(default_factory=set)
    tempo:            TempoClass = TempoClass.SINGLE_BLOCK
    fingerprint:      Optional[ObfuscationFingerprint] = None
    sigma_rules:      list[str] = field(default_factory=list)
    iocs:             list[str] = field(default_factory=list)    # extracted URLs, IPs, hashes
    baseline_anomaly: float = 0.0   # 0–100, from EnvironmentBaseline
    campaign_id:      Optional[str] = None  # set by cross-host correlator
    # DFIR enrichment fields
    beacon_profile:   Optional[BeaconProfile] = None
    ti_hits:          list[TIHit] = field(default_factory=list)
    lateral_moves:    list[LateralMove] = field(default_factory=list)
    process_tree:     list[ProcessEvent] = field(default_factory=list)
    parent_process:   str = ""          # parent process name from 4688
    event_ids_seen:   set[int] = field(default_factory=set)  # non-4104 event IDs found
    deobfuscation_passes: int = 0       # total deobfuscation passes across all blocks

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def alert_tier(self) -> str:
        s = self.weighted_score
        if s >= 80: return "P1_INCIDENT"
        if s >= 60: return "P2_ALERT"
        if s >= 40: return "P3_WARNING"
        if s > 0:   return "INFO"
        return "CLEAN"


@dataclass
class ProcessEvent:
    """A single Windows Event ID 4688 (process creation) or Sysmon 1 record."""
    event_id:      int
    host_id:       str
    timestamp:     datetime
    process_id:    int
    parent_pid:    int
    process_name:  str
    command_line:  str
    parent_name:   str = ""
    user:          str = ""
    logon_id:      str = ""
    integrity:     str = ""


@dataclass
class LogonEvent:
    """Windows Event ID 4624/4625/4648 logon record."""
    event_id:      int
    host_id:       str
    timestamp:     datetime
    target_host:   str
    username:      str
    logon_type:    int
    source_ip:     str = ""
    logon_id:      str = ""
    success:       bool = True


@dataclass
class BeaconProfile:
    """C2 beacon regularity profile derived from session timestamp analysis."""
    period_seconds:  float        # dominant callback interval
    jitter_pct:      float        # coefficient of variation (0–1)
    confidence:      float        # 0–1; >0.7 = likely beacon
    sample_count:    int          # number of inter-event intervals analysed
    framework_hint:  str = ""     # "cobalt_strike" / "metasploit" / "custom" / ""

    @property
    def is_beacon(self) -> bool:
        return self.confidence >= 0.65


@dataclass
class TIHit:
    """A threat intelligence match for an IOC."""
    ioc_value:    str
    ioc_type:     str            # "url" | "ip" | "hash" | "domain"
    source:       str            # "threatfox" | "urlhaus" | "malwarebazaar"
    malware_name: str = ""
    tags:         list[str] = field(default_factory=list)
    confidence:   int = 0        # 0–100
    first_seen:   str = ""
    threat_type:  str = ""


@dataclass
class LateralMove:
    """A detected lateral movement hop between hosts."""
    source_host:  str
    target_host:  str
    technique:    str            # technique_id e.g. LATERAL_PSREMOTING
    mitre_id:     str
    timestamp:    Optional[datetime] = None
    username:     str = ""
    evidence:     str = ""


@dataclass
class Campaign:
    """
    A cluster of Sessions sharing an ObfuscationFingerprint across 2+ hosts.
    The highest-level analytical object.
    """
    campaign_id:      str
    fingerprint_hash: str
    sessions:         list[Session] = field(default_factory=list)
    host_ids:         set[str] = field(default_factory=set)
    first_seen:       Optional[datetime] = None
    last_seen:        Optional[datetime] = None
    peak_severity:    int = 0

    @property
    def is_confirmed(self) -> bool:
        """2+ hosts, 3+ sessions = confirmed campaign (not coincidence)."""
        return len(self.host_ids) >= 2 and len(self.sessions) >= 3


# ── Rule tracking ─────────────────────────────────────────────────────────────

@dataclass
class RuleMetrics:
    """Tracks rule effectiveness over time for adaptive aging."""
    rule_name:            str
    last_true_positive:   Optional[datetime] = None
    last_false_positive:  Optional[datetime] = None
    tp_count_30d:         int = 0
    fp_count_30d:         int = 0

    @property
    def precision_30d(self) -> float:
        total = self.tp_count_30d + self.fp_count_30d
        return self.tp_count_30d / total if total > 0 else 0.0

    @property
    def days_since_tp(self) -> int:
        if not self.last_true_positive:
            return 9999
        return (datetime.utcnow() - self.last_true_positive).days

    def health(self) -> RuleHealth:
        if self.days_since_tp > 90 and self.tp_count_30d == 0:
            return RuleHealth.STALE
        if self.precision_30d < 0.10 and self.fp_count_30d > 5:
            return RuleHealth.NOISY
        if self.tp_count_30d >= 5 and self.precision_30d >= 0.70:
            return RuleHealth.HIGH_VALUE
        return RuleHealth.NOMINAL


# ── Utility ───────────────────────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string. ~3.5 = normal script, >6.0 = likely encoded."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
