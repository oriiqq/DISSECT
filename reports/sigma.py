"""
ps_classifier — Sigma rule auto-generator

Converts Session findings into valid Sigma rules (YAML format).
Each technique gets a tailored detection with correct field mappings,
condition logic, and MITRE metadata — ready to review and deploy.

Usage:
    from reports.sigma import generate_sigma_rules, SigmaBundle
    bundle = generate_sigma_rules(session)
    for rule in bundle.rules:
        print(rule.to_yaml())
    bundle.save_dir(Path("sigma_output/"))
"""
from __future__ import annotations
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import yaml
from core.models import Session, Finding, TempoClass


def _sigma_level(severity: int) -> str:
    if severity >= 85: return "critical"
    if severity >= 70: return "high"
    if severity >= 50: return "medium"
    return "low"


# ── Per-technique detection templates ─────────────────────────────────────────
_TEMPLATES: dict[str, dict] = {
    "AMSI_BYPASS_REFLECT": {
        "title": "PowerShell AMSI bypass via .NET reflection",
        "description": "Detects patching of amsiInitFailed or AmsiScanBuffer via reflection.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "sel_init": {"EventID": 4104, "ScriptBlockText|contains": "amsiInitFailed"},
            "sel_buf":  {"EventID": 4104, "ScriptBlockText|contains": "AmsiScanBuffer"},
            "sel_ref":  {"EventID": 4104, "ScriptBlockText|contains|all": ["GetField","amsi"]},
            "condition": "sel_init or sel_buf or sel_ref",
        },
        "falsepositives": ["Security research", "AMSI testing tools"],
        "tags": ["attack.defense_evasion", "attack.t1562.001"],
    },
    "AMSI_BYPASS_COM": {
        "title": "PowerShell AMSI bypass via COM object",
        "description": "Detects COM-based AMSI bypass attempts.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains|any": ["IAmsiStream","AmsiInitialize","amsi.AMSI"]},
            "condition": "selection",
        },
        "falsepositives": ["Authorised security tooling"],
        "tags": ["attack.defense_evasion", "attack.t1562.001"],
    },
    "DOWNLOAD_CRADLE_WC": {
        "title": "PowerShell download cradle via Net.WebClient",
        "description": "Detects Net.WebClient combined with IEX for remote code execution.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "sel_dl": {"EventID": 4104,
                       "ScriptBlockText|contains|any": ["DownloadString","DownloadFile","DownloadData"]},
            "sel_wc": {"EventID": 4104, "ScriptBlockText|contains": "Net.WebClient"},
            "sel_iex": {"EventID": 4104, "ScriptBlockText|contains|any": ["IEX","Invoke-Expression"]},
            "condition": "(sel_dl and sel_wc) or (sel_wc and sel_iex)",
        },
        "falsepositives": ["Legitimate installers", "IT automation scripts"],
        "tags": ["attack.command_and_control", "attack.t1105"],
    },
    "DOWNLOAD_CRADLE_BITS": {
        "title": "PowerShell BITS transfer download cradle",
        "description": "Detects BITS-based file download from PowerShell.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains|any": ["Start-BitsTransfer","BitsTransfer"]},
            "condition": "selection",
        },
        "falsepositives": ["Windows Update", "Legitimate BITS software"],
        "tags": ["attack.defense_evasion", "attack.t1197"],
    },
    "REFLECTIVE_INJECT": {
        "title": "PowerShell reflective PE injection",
        "description": "Detects reflective DLL/PE injection via PowerShell.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "sel_name": {"EventID": 4104,
                         "ScriptBlockText|contains|any": ["Invoke-ReflectivePEInjection",
                                                          "Invoke-ReflectiveDllInjection"]},
            "sel_api":  {"EventID": 4104,
                         "ScriptBlockText|contains|all": ["VirtualAlloc","WriteProcessMemory"]},
            "condition": "sel_name or sel_api",
        },
        "falsepositives": ["Authorised penetration testing"],
        "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.t1055.001"],
    },
    "SHELLCODE_MARSHAL": {
        "title": "PowerShell shellcode via Runtime.InteropServices.Marshal",
        "description": "Detects shellcode execution using AllocHGlobal + GetDelegateForFunctionPointer.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains|all": ["AllocHGlobal",
                                                           "GetDelegateForFunctionPointer"]},
            "condition": "selection",
        },
        "falsepositives": ["Advanced COM interop code"],
        "tags": ["attack.defense_evasion", "attack.t1055"],
    },
    "CRED_HARVEST": {
        "title": "PowerShell Mimikatz / credential harvesting",
        "description": "Detects Mimikatz-style credential harvesting via PowerShell.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains|any": ["sekurlsa","Invoke-Mimikatz",
                                                           "DumpCreds","lsadump::","kerberos::"]},
            "condition": "selection",
        },
        "falsepositives": ["Authorised red team engagements"],
        "tags": ["attack.credential_access", "attack.t1003.001"],
    },
    "WMI_PERSIST": {
        "title": "PowerShell WMI event subscription persistence",
        "description": "Detects WMI permanent event subscription for persistence.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains|any": ["__EventFilter",
                                                           "ActiveScriptEventConsumer",
                                                           "__FilterToConsumerBinding"]},
            "condition": "selection",
        },
        "falsepositives": ["Legitimate WMI monitoring solutions"],
        "tags": ["attack.persistence", "attack.t1546.003"],
    },
    "COBALT_STRIKE": {
        "title": "PowerShell Cobalt Strike stager indicators",
        "description": "Detects Cobalt Strike stager delivery patterns in PS script blocks.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "sel_iex": {"EventID": 4104,
                        "ScriptBlockText|contains|all": ["IEX","New-Object",
                                                         "Net.WebClient","DownloadString"]},
            "sel_gzip": {"EventID": 4104,
                         "ScriptBlockText|contains|all": ["GzipStream","FromBase64String"]},
            "sel_doit": {"EventID": 4104, "ScriptBlockText|contains": "$DoIt"},
            "condition": "sel_iex or sel_gzip or sel_doit",
        },
        "falsepositives": ["Highly unlikely in production"],
        "tags": ["attack.execution", "attack.t1059.001"],
    },
    "REVERSE_SHELL": {
        "title": "PowerShell TCP reverse shell",
        "description": "Detects reverse shell via System.Net.Sockets.TcpClient.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "sel_tcp": {"EventID": 4104,
                        "ScriptBlockText|contains|any": ["Net.Sockets.TcpClient",
                                                         "System.Net.Sockets.TcpClient"]},
            "sel_stream": {"EventID": 4104,
                           "ScriptBlockText|contains|all": ["GetStream","StreamReader"]},
            "condition": "sel_tcp or sel_stream",
        },
        "falsepositives": ["Legitimate PS network programming (rare)"],
        "tags": ["attack.command_and_control", "attack.t1059.001"],
    },
    "ETW_BYPASS": {
        "title": "PowerShell ETW bypass",
        "description": "Detects attempts to patch EtwEventWrite to disable event tracing.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains|any": ["EtwEventWrite","PatchEtw","EtwEventWriteFull"]},
            "condition": "selection",
        },
        "falsepositives": ["Security research tools"],
        "tags": ["attack.defense_evasion", "attack.t1562.006"],
    },
    "AV_EXCLUSION": {
        "title": "PowerShell Defender exclusion or disable",
        "description": "Detects adding exclusions or disabling Defender via PowerShell.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains|any": ["Add-MpPreference -ExclusionPath",
                                                           "Set-MpPreference -DisableRealtimeMonitoring",
                                                           "DisableAntiSpyware"]},
            "condition": "selection",
        },
        "falsepositives": ["Authorised system management"],
        "tags": ["attack.defense_evasion", "attack.t1562.001"],
    },
    "ENCODED_CMD": {
        "title": "PowerShell encoded command execution",
        "description": "Detects -EncodedCommand flag in PowerShell script blocks.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|re": r"-E(nc(odedCommand)?|C)\s+[A-Za-z0-9+/]{20,}"},
            "condition": "selection",
        },
        "falsepositives": ["Some legitimate admin tools", "CI/CD pipelines"],
        "tags": ["attack.execution", "attack.t1059.001"],
    },
    "HIGH_ENTROPY_BLOB": {
        "title": "PowerShell high-entropy script block (possible encoded payload)",
        "description": "Detects script blocks with large Base64-like blobs indicating encoding.",
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|re": r"[A-Za-z0-9+/]{200,}={0,2}"},
            "filter":    {"ScriptBlockText|contains|any": ["# Copyright","param(","function "]},
            "condition": "selection and not filter",
        },
        "falsepositives": ["Scripts with embedded certificates or large data blobs"],
        "tags": ["attack.execution", "attack.t1059.001"],
    },
}


# ── Sigma rule object ──────────────────────────────────────────────────────────

@dataclass
class SigmaRule:
    rule_id:        str
    title:          str
    description:    str
    status:         str
    level:          str
    logsource:      dict
    detection:      dict
    tags:           list[str]
    falsepositives: list[str]
    technique_id:   str = ""
    mitre_id:       str = ""
    session_id:     str = ""
    author:         str = "ps_classifier (auto-generated)"
    date:           str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y/%m/%d")
    )

    def to_dict(self) -> dict:
        d: dict = {
            "title":          self.title,
            "id":             self.rule_id,
            "status":         self.status,
            "description":    self.description,
            "author":         self.author,
            "date":           self.date,
            "tags":           sorted(set(self.tags)),
            "logsource":      self.logsource,
            "detection":      self.detection,
            "falsepositives": self.falsepositives,
            "level":          self.level,
        }
        if self.mitre_id:
            d["references"] = [
                "https://attack.mitre.org/techniques/"
                + self.mitre_id.replace(".", "/")
            ]
        return d

    def to_yaml(self) -> str:
        return yaml.dump(
            self.to_dict(),
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=120,
        )

    @property
    def filename(self) -> str:
        safe = re.sub(r"[^a-z0-9_]", "_", self.title.lower())
        return f"psc_{safe[:55]}_{self.rule_id[:8]}.yml"


@dataclass
class SigmaBundle:
    rules:        list[SigmaRule] = field(default_factory=list)
    session_id:   str = ""
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def save_dir(self, directory: Path) -> list[Path]:
        directory.mkdir(parents=True, exist_ok=True)
        paths = []
        for rule in self.rules:
            p = directory / rule.filename
            p.write_text(rule.to_yaml(), encoding="utf-8")
            paths.append(p)
        return paths

    def to_combined_yaml(self) -> str:
        return "\n---\n".join(r.to_yaml() for r in self.rules)

    @property
    def highest_level(self) -> str:
        for level in ("critical", "high", "medium", "low"):
            if any(r.level == level for r in self.rules):
                return level
        return "low"


# ── Public generators ─────────────────────────────────────────────────────────

def generate_sigma_rules(session: Session) -> SigmaBundle:
    """Generate one Sigma rule per unique technique in the session."""
    bundle = SigmaBundle(session_id=session.session_id)
    best: dict[str, Finding] = {}

    for block in session.blocks:
        for f in block.findings:
            if f.technique_id not in best or f.severity > best[f.technique_id].severity:
                best[f.technique_id] = f

    seen: set[str] = set()
    level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for tech_id, finding in best.items():
        tmpl = _TEMPLATES.get(tech_id) or _generic_template(finding)
        if tmpl["title"] in seen:
            continue
        seen.add(tmpl["title"])

        ts = (session.start_time.strftime("%Y-%m-%d %H:%M UTC")
              if session.start_time else "unknown")
        context = (f" Detected in session {session.session_id} on "
                   f"{session.host_id} at {ts}. "
                   f"Matched: {finding.matched_text[:80]!r}.")

        extra_tags = []
        if finding.mitre_id and f"attack.{finding.mitre_id.lower()}" not in tmpl.get("tags", []):
            extra_tags.append(f"attack.{finding.mitre_id.lower()}")

        bundle.rules.append(SigmaRule(
            rule_id=str(uuid.uuid4()),
            title=tmpl["title"],
            description=tmpl["description"] + context,
            status="experimental",
            level=_sigma_level(finding.severity),
            logsource=tmpl["logsource"],
            detection=tmpl["detection"],
            tags=tmpl.get("tags", []) + extra_tags,
            falsepositives=tmpl.get("falsepositives", ["Requires analyst review"]),
            technique_id=tech_id,
            mitre_id=finding.mitre_id,
            session_id=session.session_id,
        ))

    bundle.rules.sort(key=lambda r: level_order.get(r.level, 4))
    return bundle


def generate_sigma_for_sessions(sessions: list[Session]) -> SigmaBundle:
    """Deduplicated bundle across multiple sessions (skip sessions scoring < 40)."""
    combined = SigmaBundle()
    seen_techniques: set[str] = set()
    level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for session in sessions:
        if session.weighted_score < 40:
            continue
        for rule in generate_sigma_rules(session).rules:
            if rule.technique_id not in seen_techniques:
                seen_techniques.add(rule.technique_id)
                combined.rules.append(rule)

    combined.rules.sort(key=lambda r: level_order.get(r.level, 4))
    return combined


def _generic_template(finding: Finding) -> dict:
    return {
        "title": f"PowerShell suspicious: {finding.technique_id.replace('_',' ').lower()}",
        "description": (f"Detects {finding.technique_id} (MITRE {finding.mitre_id}). "
                        "Auto-generated by ps_classifier."),
        "logsource": {"product": "windows", "category": "ps_script_block_logging"},
        "detection": {
            "selection": {"EventID": 4104,
                          "ScriptBlockText|contains": finding.matched_text[:60]},
            "condition": "selection",
        },
        "falsepositives": ["Requires analyst review"],
        "tags": [f"attack.{finding.mitre_id.lower()}"],
    }
