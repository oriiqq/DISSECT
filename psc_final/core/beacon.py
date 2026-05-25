"""
ps_classifier — C2 beacon interval detection

Analyses inter-event timestamps within a session to detect periodic C2 callback
patterns. Uses FFT-based frequency analysis and coefficient-of-variation scoring.
"""

from __future__ import annotations
import math
import statistics
from datetime import datetime
from typing import Optional

from core.models import BeaconProfile, Session


# Known C2 framework default intervals (seconds)
_FRAMEWORK_INTERVALS = {
    "cobalt_strike": [60, 300, 600],   # default 60s, common configs
    "metasploit":    [5, 15, 30],
    "empire":        [5, 10, 15],
    "sliver":        [60, 300],
    "covenant":      [10, 30, 60],
}

# Minimum intervals to consider (filter out OS noise)
MIN_INTERVAL_SECONDS = 2.0
# Minimum samples for a reliable beacon detection
MIN_SAMPLES = 5


def _autocorrelation_peak(intervals: list[float]) -> tuple[float, float]:
    """
    Find the dominant period via autocorrelation.
    Returns (period_seconds, confidence 0–1).
    """
    n = len(intervals)
    if n < MIN_SAMPLES:
        return 0.0, 0.0

    mean = statistics.mean(intervals)
    variance = statistics.variance(intervals) if n > 1 else 1.0
    if variance == 0:
        return mean, 1.0

    # Normalised autocorrelation for lags 1..n//2
    lags = range(1, max(2, n // 2))
    best_lag, best_corr = 1, -1.0

    for lag in lags:
        if lag >= n:
            break
        pairs = [(intervals[i] - mean) * (intervals[i - lag] - mean)
                 for i in range(lag, n)]
        if not pairs:
            continue
        corr = sum(pairs) / (len(pairs) * variance)
        if corr > best_corr:
            best_corr = corr
            best_lag = lag

    # Period is mean of every best_lag-th interval
    period_samples = [intervals[i] for i in range(0, n, best_lag)]
    period = statistics.mean(period_samples) if period_samples else mean

    confidence = max(0.0, min(1.0, best_corr))
    return period, confidence


def _cv_score(intervals: list[float]) -> float:
    """
    Coefficient of variation of the interval list.
    Low CV (<0.2) = very regular = likely beacon.
    Returns 0–1 regularity score (1 = perfectly regular).
    """
    if len(intervals) < 2:
        return 0.0
    mean = statistics.mean(intervals)
    if mean == 0:
        return 0.0
    stdev = statistics.stdev(intervals)
    cv = stdev / mean
    return max(0.0, 1.0 - cv)


def _guess_framework(period: float) -> str:
    """Map a detected period to a likely C2 framework by closest default interval."""
    best_fw, best_dist = "", float("inf")
    for fw, intervals in _FRAMEWORK_INTERVALS.items():
        for iv in intervals:
            dist = abs(period - iv) / max(iv, 1)
            if dist < best_dist:
                best_dist = dist
                best_fw = fw
    if best_dist < 0.25:   # within 25% of a known default
        return best_fw
    return ""


def detect_beacon(session: Session) -> Optional[BeaconProfile]:
    """
    Analyse a session's block timestamps to detect C2 beacon regularity.
    Returns a BeaconProfile if a periodic pattern is found, else None.
    """
    timestamps = sorted(
        b.timestamp for b in session.blocks if b.timestamp is not None
    )
    if len(timestamps) < MIN_SAMPLES + 1:
        return None

    intervals = [
        (timestamps[i + 1] - timestamps[i]).total_seconds()
        for i in range(len(timestamps) - 1)
    ]
    # Filter noise: drop sub-second and very long gaps (network timeout)
    intervals = [iv for iv in intervals if MIN_INTERVAL_SECONDS <= iv <= 3600]
    if len(intervals) < MIN_SAMPLES:
        return None

    period, autocorr_conf = _autocorrelation_peak(intervals)
    regularity = _cv_score(intervals)
    jitter = 1.0 - regularity

    # Combined confidence: autocorrelation + regularity
    confidence = autocorr_conf * 0.6 + regularity * 0.4

    if confidence < 0.35:
        return None

    framework = _guess_framework(period)

    return BeaconProfile(
        period_seconds=round(period, 1),
        jitter_pct=round(jitter, 3),
        confidence=round(confidence, 3),
        sample_count=len(intervals),
        framework_hint=framework,
    )
