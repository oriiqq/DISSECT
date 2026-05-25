"""
ps_classifier — YARA rule auto-generator

Converts Session findings into YARA rules targeting PowerShell script block text.
Each technique gets a tailored rule with proper string patterns and conditions.
"""
from __future__ import annotations
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from core.models import Session, Finding


def _yara_severity(severity: int) -> str:
    if severity >= 85: return "critical"
    if severity >= 70: return "high"
    if severity >= 50: return "medium"
    return "low"


# ── Per-technique YARA templates ───────────────────────────────────────────────
# Each entry: varname -> (type, pattern, modifiers)
#   type 's' = plain string, 'r' = regex (written as /pattern/)
_TEMPLATES: dict[str, dict] = {
    "AMSI_BYPASS_REFLECT": {
        "name": "PSC_AMSI_Bypass_Reflect",
        "tags": ["powershell", "defense_evasion", "T1562_001"],
        "description": "PowerShell AMSI bypass via .NET reflection — patches amsiInitFailed or AmsiScanBuffer",
        "mitre": "T1562.001",
        "strings": {
            "$amsi_init": ("s", "amsiInitFailed", "nocase"),
            "$amsi_buf":  ("s", "AmsiScanBuffer",  "nocase"),
            "$get_field": ("s", "GetField",         "nocase"),
            "$amsi_ns":   ("s", "amsi",             "nocase wide"),
        },
        "condition": "$amsi_init or $amsi_buf or ($get_field and $amsi_ns)",
    },
    "AMSI_BYPASS_COM": {
        "name": "PSC_AMSI_Bypass_COM",
        "tags": ["powershell", "defense_evasion", "T1562_001"],
        "description": "PowerShell AMSI bypass via COM object",
        "mitre": "T1562.001",
        "strings": {
            "$iamsi":   ("s", "IAmsiStream",    "nocase"),
            "$amsi_in": ("s", "AmsiInitialize", "nocase"),
            "$amsi_co": ("s", "amsi.AMSI",      "nocase"),
        },
        "condition": "any of them",
    },
    "DOWNLOAD_CRADLE_WC": {
        "name": "PSC_Download_Cradle_WebClient",
        "tags": ["powershell", "command_and_control", "T1105"],
        "description": "PowerShell download cradle via Net.WebClient combined with IEX",
        "mitre": "T1105",
        "strings": {
            "$dl_str":  ("s", "DownloadString",    "nocase"),
            "$dl_file": ("s", "DownloadFile",      "nocase"),
            "$dl_data": ("s", "DownloadData",      "nocase"),
            "$webcli":  ("s", "Net.WebClient",     "nocase"),
            "$iex":     ("s", "IEX",               "nocase"),
            "$inv_exp": ("s", "Invoke-Expression", "nocase"),
        },
        "condition": "($webcli and ($dl_str or $dl_file or $dl_data)) or ($webcli and ($iex or $inv_exp))",
    },
    "DOWNLOAD_CRADLE_BITS": {
        "name": "PSC_Download_Cradle_BITS",
        "tags": ["powershell", "defense_evasion", "T1197"],
        "description": "PowerShell BITS-based file download cradle",
        "mitre": "T1197",
        "strings": {
            "$bits1": ("s", "Start-BitsTransfer", "nocase"),
            "$bits2": ("s", "BitsTransfer",       "nocase"),
        },
        "condition": "any of them",
    },
    "REFLECTIVE_INJECT": {
        "name": "PSC_Reflective_PE_Injection",
        "tags": ["powershell", "defense_evasion", "privilege_escalation", "T1055_001"],
        "description": "PowerShell reflective PE/DLL injection",
        "mitre": "T1055.001",
        "strings": {
            "$rpe":  ("s", "Invoke-ReflectivePEInjection",  "nocase"),
            "$rdll": ("s", "Invoke-ReflectiveDllInjection", "nocase"),
            "$va":   ("s", "VirtualAlloc",                  "nocase"),
            "$wpm":  ("s", "WriteProcessMemory",            "nocase"),
        },
        "condition": "$rpe or $rdll or ($va and $wpm)",
    },
    "SHELLCODE_MARSHAL": {
        "name": "PSC_Shellcode_Marshal",
        "tags": ["powershell", "defense_evasion", "T1055"],
        "description": "PowerShell shellcode execution via Runtime.InteropServices.Marshal",
        "mitre": "T1055",
        "strings": {
            "$alloc": ("s", "AllocHGlobal",                  "nocase"),
            "$dfp":   ("s", "GetDelegateForFunctionPointer", "nocase"),
        },
        "condition": "all of them",
    },
    "CRED_HARVEST": {
        "name": "PSC_Credential_Harvesting",
        "tags": ["powershell", "credential_access", "T1003_001"],
        "description": "PowerShell Mimikatz-style credential harvesting",
        "mitre": "T1003.001",
        "strings": {
            "$sek":  ("s", "sekurlsa",        "nocase"),
            "$mimi": ("s", "Invoke-Mimikatz", "nocase"),
            "$dump": ("s", "DumpCreds",       "nocase"),
            "$lsa":  ("s", "lsadump::",       "nocase"),
            "$kerb": ("s", "kerberos::",      "nocase"),
        },
        "condition": "any of them",
    },
    "WMI_PERSIST": {
        "name": "PSC_WMI_Event_Persistence",
        "tags": ["powershell", "persistence", "T1546_003"],
        "description": "PowerShell WMI event subscription for persistence",
        "mitre": "T1546.003",
        "strings": {
            "$evtf": ("s", "__EventFilter",             "nocase"),
            "$asec": ("s", "ActiveScriptEventConsumer", "nocase"),
            "$ftcb": ("s", "__FilterToConsumerBinding", "nocase"),
        },
        "condition": "any of them",
    },
    "COBALT_STRIKE": {
        "name": "PSC_CobaltStrike_Stager",
        "tags": ["powershell", "execution", "T1059_001"],
        "description": "PowerShell Cobalt Strike stager delivery patterns",
        "mitre": "T1059.001",
        "strings": {
            "$iex":    ("s", "IEX",              "nocase"),
            "$newobj": ("s", "New-Object",       "nocase"),
            "$webcli": ("s", "Net.WebClient",    "nocase"),
            "$dlstr":  ("s", "DownloadString",   "nocase"),
            "$gzip":   ("s", "GzipStream",       "nocase"),
            "$b64":    ("s", "FromBase64String",  "nocase"),
            "$doit":   ("s", "$DoIt",            "nocase"),
        },
        "condition": "($iex and $newobj and $webcli and $dlstr) or ($gzip and $b64) or $doit",
    },
    "REVERSE_SHELL": {
        "name": "PSC_TCP_Reverse_Shell",
        "tags": ["powershell", "command_and_control", "T1059_001"],
        "description": "PowerShell TCP reverse shell via System.Net.Sockets.TcpClient",
        "mitre": "T1059.001",
        "strings": {
            "$tcp1":   ("s", "Net.Sockets.TcpClient",        "nocase"),
            "$tcp2":   ("s", "System.Net.Sockets.TcpClient", "nocase"),
            "$stream": ("s", "GetStream",                    "nocase"),
            "$reader": ("s", "StreamReader",                 "nocase"),
        },
        "condition": "$tcp1 or $tcp2 or ($stream and $reader)",
    },
    "ETW_BYPASS": {
        "name": "PSC_ETW_Bypass",
        "tags": ["powershell", "defense_evasion", "T1562_006"],
        "description": "PowerShell ETW event tracing bypass via EtwEventWrite patching",
        "mitre": "T1562.006",
        "strings": {
            "$etw1": ("s", "EtwEventWrite",     "nocase"),
            "$etw2": ("s", "PatchEtw",          "nocase"),
            "$etw3": ("s", "EtwEventWriteFull", "nocase"),
        },
        "condition": "any of them",
    },
    "AV_EXCLUSION": {
        "name": "PSC_Defender_Disable",
        "tags": ["powershell", "defense_evasion", "T1562_001"],
        "description": "PowerShell Windows Defender exclusion or real-time monitoring disable",
        "mitre": "T1562.001",
        "strings": {
            "$excl": ("s", "Add-MpPreference -ExclusionPath",             "nocase"),
            "$dis":  ("s", "Set-MpPreference -DisableRealtimeMonitoring", "nocase"),
            "$disa": ("s", "DisableAntiSpyware",                          "nocase"),
        },
        "condition": "any of them",
    },
    "ENCODED_CMD": {
        "name": "PSC_Encoded_Command",
        "tags": ["powershell", "execution", "T1059_001"],
        "description": "PowerShell -EncodedCommand flag for obfuscated payload execution",
        "mitre": "T1059.001",
        "strings": {
            "$enc1": ("r", r"-E(nc(odedCommand)?|C)\s+[A-Za-z0-9+\/]{20,}", "nocase"),
        },
        "condition": "any of them",
    },
    "HIGH_ENTROPY_BLOB": {
        "name": "PSC_High_Entropy_Blob",
        "tags": ["powershell", "execution", "T1059_001"],
        "description": "PowerShell script block containing a large Base64-encoded payload blob",
        "mitre": "T1059.001",
        "strings": {
            "$b64": ("r", r"[A-Za-z0-9+\/]{200,}={0,2}", ""),
        },
        "condition": "any of them",
    },
}


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class YaraRule:
    rule_id:      str
    name:         str
    tags:         list[str]
    description:  str
    mitre:        str
    severity:     str
    strings:      dict
    condition:    str
    technique_id: str = ""
    session_id:   str = ""
    author:       str = "ps_classifier (auto-generated)"
    date:         str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d")
    )

    def to_yara(self) -> str:
        tag_str = " ".join(self.tags)
        lines = [f"rule {self.name} : {tag_str} {{"]
        lines.append("    meta:")
        lines.append(f'        description     = "{self.description}"')
        lines.append(f'        author          = "{self.author}"')
        lines.append(f'        date            = "{self.date}"')
        lines.append(f'        severity        = "{self.severity}"')
        lines.append(f'        mitre_technique = "{self.mitre}"')
        lines.append("    strings:")
        for varname, (typ, pattern, mods) in self.strings.items():
            mods_str = f" {mods}" if mods else ""
            if typ == "r":
                lines.append(f"        {varname} = /{pattern}/{mods_str.strip()}")
            else:
                lines.append(f'        {varname} = "{pattern}"{mods_str}')
        lines.append("    condition:")
        lines.append(f"        {self.condition}")
        lines.append("}")
        return "\n".join(lines)


@dataclass
class YaraBundle:
    rules:        list[YaraRule] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    def to_yara(self) -> str:
        if not self.rules:
            return "// No rules generated — run an analysis first.\n"
        header = (
            f"// ps_classifier — YARA rules\n"
            f"// Generated: {self.generated_at}\n"
            f"// Rules:     {len(self.rules)}\n\n"
        )
        return header + "\n\n".join(r.to_yara() for r in self.rules)


# ── Public generators ─────────────────────────────────────────────────────────

def generate_yara_rules(session: Session) -> YaraBundle:
    """One YARA rule per unique technique found in a session."""
    bundle = YaraBundle()
    best: dict[str, Finding] = {}

    for block in session.blocks:
        for f in block.findings:
            if f.technique_id not in best or f.severity > best[f.technique_id].severity:
                best[f.technique_id] = f

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    seen: set[str] = set()

    for tech_id, finding in best.items():
        tmpl = _TEMPLATES.get(tech_id) or _generic_template(finding)
        if tmpl["name"] in seen:
            continue
        seen.add(tmpl["name"])

        bundle.rules.append(YaraRule(
            rule_id=str(uuid.uuid4()),
            name=tmpl["name"],
            tags=tmpl["tags"],
            description=tmpl["description"],
            mitre=tmpl.get("mitre", finding.mitre_id),
            severity=_yara_severity(finding.severity),
            strings=tmpl["strings"],
            condition=tmpl["condition"],
            technique_id=tech_id,
            session_id=session.session_id,
        ))

    bundle.rules.sort(key=lambda r: severity_order.get(r.severity, 4))
    return bundle


def generate_yara_for_sessions(sessions: list[Session]) -> YaraBundle:
    """Deduplicated bundle across all sessions scoring >= 40."""
    combined = YaraBundle()
    seen_techniques: set[str] = set()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for session in sessions:
        if session.weighted_score < 40:
            continue
        for rule in generate_yara_rules(session).rules:
            if rule.technique_id not in seen_techniques:
                seen_techniques.add(rule.technique_id)
                combined.rules.append(rule)

    combined.rules.sort(key=lambda r: severity_order.get(r.severity, 4))
    return combined


def _generic_template(finding: Finding) -> dict:
    safe_text = re.sub(r'[^\w\s\-.]', '', finding.matched_text[:60])
    return {
        "name": f"PSC_{finding.technique_id}",
        "tags": ["powershell", f"T{finding.mitre_id.replace('.', '_')}"],
        "description": (
            f"Detects {finding.technique_id.replace('_', ' ').lower()} "
            f"(MITRE {finding.mitre_id}). Auto-generated by ps_classifier."
        ),
        "mitre": finding.mitre_id,
        "strings": {"$match": ("s", safe_text[:60], "nocase")},
        "condition": "any of them",
    }
