from __future__ import annotations
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

_URL_RE  = re.compile(r'^https?://', re.IGNORECASE)
_IP_RE   = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_HASH_RE = re.compile(r'^[0-9a-fA-F]{32,64}$')
_PATH_RE = re.compile(r'^[A-Za-z]:\\', re.IGNORECASE)


def _ioc_type(value: str) -> str:
    if _URL_RE.match(value):  return "url"
    if _IP_RE.match(value):   return "ip"
    if _HASH_RE.match(value): return "hash"
    if _PATH_RE.match(value): return "path"
    return "other"


@dataclass
class IOCEntry:
    value:    str
    ioc_type: str
    count:    int
    sessions: List[str]


@dataclass
class IOCBundle:
    entries:      List[IOCEntry] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    def by_type(self, ioc_type: str) -> List[IOCEntry]:
        return [e for e in self.entries if e.ioc_type == ioc_type]

    def counts(self) -> dict:
        from collections import Counter
        c = Counter(e.ioc_type for e in self.entries)
        return {"url": c["url"], "ip": c["ip"], "hash": c["hash"], "path": c["path"]}

    def to_csv(self) -> str:
        lines = ["type,value,count,sessions"]
        for e in self.entries:
            lines.append(f'{e.ioc_type},"{e.value}",{e.count},"{"|".join(e.sessions)}"')
        return "\n".join(lines)

    def to_text(self) -> str:
        lines = [f"# IOC Export — {self.generated_at}", ""]
        for t in ("url", "ip", "hash", "path"):
            typed = self.by_type(t)
            if typed:
                lines.append(f"## {t.upper()}s ({len(typed)})")
                for e in typed:
                    lines.append(e.value)
                lines.append("")
        return "\n".join(lines)


def generate_ioc_hub(sessions) -> IOCBundle:
    from collections import defaultdict
    ioc_map: dict = defaultdict(lambda: {"count": 0, "sessions": set(), "type": ""})

    for s in sessions:
        for v in s.iocs:
            v = v.strip()
            if not v:
                continue
            ioc_map[v]["count"] += 1
            ioc_map[v]["sessions"].add(s.session_id)
            if not ioc_map[v]["type"]:
                ioc_map[v]["type"] = _ioc_type(v)

    entries = [
        IOCEntry(
            value=k,
            ioc_type=v["type"],
            count=v["count"],
            sessions=sorted(v["sessions"]),
        )
        for k, v in ioc_map.items()
        if k.strip()
    ]
    entries.sort(key=lambda e: (-e.count, e.ioc_type, e.value))
    return IOCBundle(entries=entries)
