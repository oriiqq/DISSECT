"""
ps_classifier — Threat Intelligence enrichment

Queries abuse.ch free APIs (no API key required):
  - ThreatFox: IOC → malware family lookup
  - URLhaus: URL/domain → malware distribution lookup
  - MalwareBazaar: file hash → malware sample lookup

Results are cached in memory for the lifetime of the process to avoid
re-querying the same indicator multiple times in one analysis run.
"""

from __future__ import annotations
import hashlib
import logging
import re
import time
import urllib.request
import urllib.error
import json
from typing import Optional

from core.models import TIHit, Session

log = logging.getLogger(__name__)

# In-memory cache: ioc_value → (TIHit | None, timestamp)
_CACHE: dict[str, tuple[Optional[TIHit], float]] = {}
CACHE_TTL = 3600  # 1 hour
REQUEST_TIMEOUT = 6  # seconds

# Patterns to decide what kind of IOC we have
_URL_RE   = re.compile(r'^https?://', re.IGNORECASE)
_IP_RE    = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
_HASH_RE  = re.compile(r'^[0-9a-fA-F]{32,64}$')
_DOM_RE   = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')


def _classify_ioc(value: str) -> str:
    v = value.strip()
    if _URL_RE.match(v):
        return "url"
    if _IP_RE.match(v):
        return "ip"
    if _HASH_RE.match(v):
        return "hash"
    if _DOM_RE.match(v):
        return "domain"
    return "unknown"


def _http_post(url: str, payload: dict) -> Optional[dict]:
    """Simple synchronous HTTP POST returning parsed JSON or None."""
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "ps_classifier/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        log.debug("TI HTTP error [%s]: %s", url, exc)
        return None


def _query_threatfox(ioc: str, ioc_type: str) -> Optional[TIHit]:
    """Query ThreatFox for any IOC type."""
    resp = _http_post(
        "https://threatfox-api.abuse.ch/api/v1/",
        {"query": "search_ioc", "search_term": ioc},
    )
    if not resp or resp.get("query_status") != "ok":
        return None
    data = resp.get("data") or []
    if not data:
        return None
    hit = data[0]
    return TIHit(
        ioc_value=ioc,
        ioc_type=ioc_type,
        source="threatfox",
        malware_name=hit.get("malware_printable", ""),
        tags=hit.get("tags") or [],
        confidence=int(hit.get("confidence_level", 0)),
        first_seen=hit.get("first_seen", ""),
        threat_type=hit.get("threat_type", ""),
    )


def _query_urlhaus(url: str) -> Optional[TIHit]:
    """Query URLhaus for a URL."""
    resp = _http_post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        {"url": url},
    )
    if not resp or resp.get("query_status") not in ("is_listed",):
        return None
    return TIHit(
        ioc_value=url,
        ioc_type="url",
        source="urlhaus",
        malware_name=resp.get("threat", ""),
        tags=[t.get("tag", "") for t in (resp.get("tags") or [])],
        confidence=80,
        first_seen=resp.get("date_added", ""),
        threat_type="malware_distribution",
    )


def _query_malwarebazaar(file_hash: str) -> Optional[TIHit]:
    """Query MalwareBazaar for a file hash."""
    resp = _http_post(
        "https://mb-api.abuse.ch/api/v1/",
        {"query": "get_info", "hash": file_hash},
    )
    if not resp or resp.get("query_status") != "hash_found":
        return None
    data = resp.get("data") or [{}]
    hit = data[0]
    return TIHit(
        ioc_value=file_hash,
        ioc_type="hash",
        source="malwarebazaar",
        malware_name=hit.get("signature", ""),
        tags=hit.get("tags") or [],
        confidence=90,
        first_seen=hit.get("first_seen", ""),
        threat_type=hit.get("file_type", ""),
    )


def lookup_ioc(ioc_value: str) -> Optional[TIHit]:
    """
    Look up a single IOC across available TI feeds.
    Results are cached per process lifetime.
    """
    key = ioc_value.strip().lower()
    cached = _CACHE.get(key)
    if cached is not None:
        result, ts = cached
        if time.time() - ts < CACHE_TTL:
            return result

    ioc_type = _classify_ioc(ioc_value)
    result: Optional[TIHit] = None

    try:
        if ioc_type == "url":
            result = _query_urlhaus(ioc_value) or _query_threatfox(ioc_value, "url")
        elif ioc_type == "hash":
            result = _query_malwarebazaar(ioc_value) or _query_threatfox(ioc_value, "hash")
        elif ioc_type in ("ip", "domain"):
            result = _query_threatfox(ioc_value, ioc_type)
    except Exception as exc:
        log.debug("TI lookup failed for %s: %s", ioc_value, exc)

    _CACHE[key] = (result, time.time())
    return result


def enrich_with_ti(session: Session, max_iocs: int = 20) -> Session:
    """
    Look up all IOCs in the session against TI feeds.
    Populates session.ti_hits in place.
    Limits to max_iocs to stay within API rate limits.
    """
    hits = []
    for ioc in session.iocs[:max_iocs]:
        hit = lookup_ioc(ioc)
        if hit:
            hits.append(hit)
    session.ti_hits = hits
    return session
