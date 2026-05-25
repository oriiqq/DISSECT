"""
ps_classifier — environment baseline

Builds a per-organisation PowerShell vocabulary from observed benign activity.
Used to suppress false positives on legitimate automation and raise sensitivity
to novel tooling.

Usage:
    baseline = EnvironmentBaseline.load("baseline.json")   # or start fresh
    baseline.ingest_benign(block)                           # during observation period
    anomaly_score = baseline.anomaly_score(block)           # during analysis
    baseline.save("baseline.json")
"""

from __future__ import annotations
import json
import logging
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from core.models import ScriptBlock, shannon_entropy

log = logging.getLogger(__name__)

# Cmdlets so universal they carry no anomaly signal
_UNIVERSAL_CMDLETS = frozenset({
    "write-host", "write-output", "write-verbose", "write-error",
    "get-item", "set-item", "get-childitem", "remove-item",
    "get-content", "set-content", "out-file", "out-null",
    "if", "else", "foreach", "while", "for", "return",
    "param", "function", "try", "catch", "finally",
    "import-module", "export-modulemember",
})

_CMDLET_RE = re.compile(
    r'\b(?:Invoke|Get|Set|New|Remove|Add|Start|Stop|Test|Out|'
    r'Write|Read|Select|Where|ForEach|Sort|Group|Measure|'
    r'Convert|Export|Import|Register|Unregister|'
    r'Enable|Disable|Clear|Copy|Move|Rename|'
    r'Install|Uninstall|Publish|Update|'
    r'Enter|Exit|Push|Pop|'
    r'Format|Compare|Join|Split)-\w+',
    re.IGNORECASE
)


class EnvironmentBaseline:
    """
    Per-environment PowerShell baseline.

    Attributes:
        cmdlet_frequency:      how often each cmdlet is seen org-wide
        known_script_hashes:   exact block hashes from known-good scripts
        known_paths:           script file paths seen in production
        known_entropy_ranges:  typical entropy distribution for benign scripts
        observation_count:     number of blocks ingested into baseline
        created_at:            when this baseline was first built
    """

    def __init__(self):
        self.cmdlet_frequency:   Counter = Counter()
        self.known_script_hashes: set[str] = set()
        self.known_paths:         set[str] = set()
        self._entropy_samples:   list[float] = []
        self.observation_count:  int = 0
        self.created_at:         str = datetime.utcnow().isoformat()

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def ingest_benign(self, block: ScriptBlock) -> None:
        """
        Record a known-benign ScriptBlock into the baseline.
        Call this during the observation period, or when analysts mark FPs.
        """
        cmdlets = self._extract_cmdlets(block.decoded_text)
        self.cmdlet_frequency.update(cmdlets)
        self.known_script_hashes.add(block.block_hash())
        if block.path:
            self.known_paths.add(self._normalize_path(block.path))
        self._entropy_samples.append(block.entropy)
        self.observation_count += 1

    def ingest_batch(self, blocks: list[ScriptBlock]) -> None:
        for b in blocks:
            self.ingest_benign(b)
        log.info("Baseline: ingested %d blocks (total %d)", len(blocks), self.observation_count)

    # ── Scoring ───────────────────────────────────────────────────────────────

    def anomaly_score(self, block: ScriptBlock) -> float:
        """
        How unusual is this block relative to the org baseline?
        Returns 0.0 (known-good) to 100.0 (completely novel).

        Components:
          - Exact hash match:       → 0.0 (suppress entirely)
          - Known path match:       → ×0.3 multiplier (trusted source)
          - Cmdlet rarity ratio:    → primary signal
          - Entropy outlier:        → secondary signal
        """
        if self.observation_count < 100:
            # Baseline not yet meaningful — return 0 to avoid suppressing real alerts
            return 0.0

        # Exact content match — known-good script, suppress
        if block.block_hash() in self.known_script_hashes:
            return 0.0

        # Extract cmdlets and measure rarity
        cmdlets = self._extract_cmdlets(block.decoded_text)
        if not cmdlets:
            return 0.0

        # Rarity: how many of this block's cmdlets have we seen fewer than 5 times?
        rare      = [c for c in cmdlets if self.cmdlet_frequency.get(c, 0) < 5
                     and c not in _UNIVERSAL_CMDLETS]
        never     = [c for c in cmdlets if self.cmdlet_frequency.get(c, 0) == 0
                     and c not in _UNIVERSAL_CMDLETS]

        rarity_ratio = (len(rare) * 1.0 + len(never) * 1.5) / max(len(cmdlets), 1)
        rarity_score = min(100.0, rarity_ratio * 80)

        # Entropy outlier: is this block unusually high-entropy vs org baseline?
        entropy_bonus = 0.0
        if len(self._entropy_samples) > 50:
            mean_e = sum(self._entropy_samples) / len(self._entropy_samples)
            if block.entropy > mean_e * 1.5 and block.entropy > 4.5:
                entropy_bonus = 15.0

        score = rarity_score + entropy_bonus

        # Trusted path discount: known production script path
        if block.path and self._normalize_path(block.path) in self.known_paths:
            score *= 0.3

        return min(100.0, score)

    def is_known_good(self, block: ScriptBlock) -> bool:
        """True if this block is an exact match to a previously seen benign block."""
        return block.block_hash() in self.known_script_hashes

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: str | Path) -> None:
        """Serialize baseline to JSON for reuse across runs."""
        data = {
            "created_at":       self.created_at,
            "observation_count": self.observation_count,
            "cmdlet_frequency": dict(self.cmdlet_frequency.most_common(5000)),
            "known_script_hashes": list(self.known_script_hashes),
            "known_paths":      list(self.known_paths),
            "entropy_samples":  self._entropy_samples[-2000:],  # keep last 2000
        }
        Path(path).write_text(json.dumps(data, indent=2))
        log.info("Baseline saved to %s (%d observations)", path, self.observation_count)

    @classmethod
    def load(cls, path: str | Path) -> "EnvironmentBaseline":
        """Load a previously saved baseline."""
        bl = cls()
        data = json.loads(Path(path).read_text())
        bl.created_at         = data.get("created_at", bl.created_at)
        bl.observation_count  = data.get("observation_count", 0)
        bl.cmdlet_frequency   = Counter(data.get("cmdlet_frequency", {}))
        bl.known_script_hashes = set(data.get("known_script_hashes", []))
        bl.known_paths        = set(data.get("known_paths", []))
        bl._entropy_samples   = data.get("entropy_samples", [])
        log.info("Baseline loaded from %s (%d observations)", path, bl.observation_count)
        return bl

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_cmdlets(text: str) -> list[str]:
        return [m.lower() for m in _CMDLET_RE.findall(text)]

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalise a script path for comparison (lowercase, strip drive letter)."""
        return re.sub(r'^[A-Za-z]:\\', '', path).lower().replace('\\', '/')

    def summary(self) -> dict:
        """Human-readable baseline summary."""
        return {
            "observations":    self.observation_count,
            "unique_cmdlets":  len(self.cmdlet_frequency),
            "known_hashes":    len(self.known_script_hashes),
            "known_paths":     len(self.known_paths),
            "top_cmdlets":     [c for c, _ in self.cmdlet_frequency.most_common(10)],
            "created_at":      self.created_at,
        }
