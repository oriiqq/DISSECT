"""
ps_classifier — pattern library + classification engine

Rules are loaded from patterns/rules.yaml at startup.
Each rule is applied to decoded_text (post-deobfuscation).
"""

from __future__ import annotations
import re
import yaml
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.models import Finding, ScriptBlock, shannon_entropy

log = logging.getLogger(__name__)

RULES_FILE = Path(__file__).parent.parent / "patterns" / "rules.yaml"


# ── Rule dataclass ────────────────────────────────────────────────────────────

@dataclass
class Rule:
    name:         str
    technique_id: str
    mitre_id:     str
    severity:     int           # base severity 0–100
    patterns:     list[str]     # regex patterns (any match = rule fires)
    description:  str = ""
    tags:         list[str] = field(default_factory=list)
    _compiled:    list = field(default_factory=list, repr=False, init=False)

    def __post_init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.patterns]

    def match(self, text: str) -> list[tuple[str, str]]:
        """Returns list of (matched_text, context) tuples for all pattern hits."""
        hits = []
        for rx in self._compiled:
            for m in rx.finditer(text):
                start   = max(0, m.start() - 40)
                end     = min(len(text), m.end() + 40)
                context = text[start:end].replace('\n', ' ').strip()
                hits.append((m.group(0)[:120], context[:160]))
        return hits


# ── Rule loader ───────────────────────────────────────────────────────────────

def load_rules(path: Path = RULES_FILE) -> list[Rule]:
    """Load rules from YAML. Falls back to built-in rules if file not found."""
    if path.exists():
        with path.open() as f:
            data = yaml.safe_load(f)
        rules = [Rule(**r) for r in data.get("rules", [])]
        log.info("Loaded %d rules from %s", len(rules), path)
        return rules
    log.warning("rules.yaml not found at %s — using built-in rules", path)
    return _builtin_rules()


def _builtin_rules() -> list[Rule]:
    """Fallback rules — always available without the YAML file."""
    return [
        Rule(
            name="amsi_bypass_reflection",
            technique_id="AMSI_BYPASS_REFLECT",
            mitre_id="T1562.001",
            severity=90,
            description="AMSI bypass via .NET reflection patching amsiInitFailed or AmsiScanBuffer",
            tags=["amsi", "bypass", "reflection"],
            patterns=[
                r'amsiInitFailed',
                r'AmsiScanBuffer',
                r'amsiContext',
                r'\[Ref\]\.Assembly\.GetType\s*\(\s*[\'"]System\.Management\.Automation\.',
                r'GetField\s*\(\s*[\'"]amsi',
                r'amsi\.dll',
            ],
        ),
        Rule(
            name="amsi_bypass_com",
            technique_id="AMSI_BYPASS_COM",
            mitre_id="T1562.001",
            severity=90,
            description="AMSI bypass via COM object manipulation",
            tags=["amsi", "bypass", "com"],
            patterns=[
                r'IAmsiStream',
                r'amsi\.AMSI',
                r'AmsiInitialize',
                r'AmsiOpenSession',
            ],
        ),
        Rule(
            name="download_cradle_webclient",
            technique_id="DOWNLOAD_CRADLE_WC",
            mitre_id="T1105",
            severity=75,
            description="Remote payload download via Net.WebClient",
            tags=["download", "cradle", "webclient"],
            patterns=[
                r'Net\.WebClient',
                r'DownloadString\s*\(',
                r'DownloadFile\s*\(',
                r'DownloadData\s*\(',
                r'OpenRead\s*\(\s*[\'"]https?://',
            ],
        ),
        Rule(
            name="download_cradle_bits",
            technique_id="DOWNLOAD_CRADLE_BITS",
            mitre_id="T1197",
            severity=70,
            description="Download via Background Intelligent Transfer Service",
            tags=["download", "bits"],
            patterns=[
                r'Start-BitsTransfer',
                r'Import-Module\s+BitsTransfer',
            ],
        ),
        Rule(
            name="download_cradle_invoke_webrequest",
            technique_id="DOWNLOAD_CRADLE_IWR",
            mitre_id="T1105",
            severity=65,
            description="Download via Invoke-WebRequest / curl alias",
            tags=["download", "cradle"],
            patterns=[
                r'Invoke-WebRequest\s+.*-Uri\s+[\'"]https?://',
                r'\bcurl\b.*https?://',
                r'wget\s+https?://',
            ],
        ),
        Rule(
            name="reflective_pe_injection",
            technique_id="REFLECTIVE_INJECT",
            mitre_id="T1055.001",
            severity=95,
            description="Reflective PE injection pattern",
            tags=["injection", "pe", "reflective"],
            patterns=[
                r'Invoke-ReflectivePEInjection',
                r'Invoke-ReflectiveDllInjection',
                r'VirtualAlloc.*WriteProcessMemory',
                r'NtAllocateVirtualMemory',
            ],
        ),
        Rule(
            name="shellcode_via_marshal",
            technique_id="SHELLCODE_MARSHAL",
            mitre_id="T1055",
            severity=95,
            description="Shellcode execution via Runtime.InteropServices.Marshal",
            tags=["shellcode", "marshal", "injection"],
            patterns=[
                r'Runtime\.InteropServices\.Marshal',
                r'AllocHGlobal\s*\(',
                r'GetDelegateForFunctionPointer\s*\(',
                r'UnsafeAddrOfPinnedArrayElement',
            ],
        ),
        Rule(
            name="clm_bypass",
            technique_id="CLM_BYPASS",
            mitre_id="T1059.001",
            severity=80,
            description="Constrained Language Mode bypass attempt",
            tags=["clm", "bypass", "languagemode"],
            patterns=[
                r'__PSLockDownPolicy',
                r'LanguageMode.*FullLanguage',
                r'SessionState\.LanguageMode',
                r'RunspaceConfiguration',
                r'Add-Type\s+.*-Assembly\s+',
            ],
        ),
        Rule(
            name="credential_harvest_mimikatz",
            technique_id="CRED_HARVEST",
            mitre_id="T1003.001",
            severity=90,
            description="Mimikatz or sekurlsa credential harvesting",
            tags=["credentials", "mimikatz", "lsass"],
            patterns=[
                r'sekurlsa',
                r'Invoke-Mimikatz',
                r'DumpCreds',
                r'privilege::debug',
                r'lsadump::',
                r'kerberos::',
                r'Get-Process\s+lsass',
            ],
        ),
        Rule(
            name="wmi_persistence",
            technique_id="WMI_PERSIST",
            mitre_id="T1546.003",
            severity=80,
            description="WMI event subscription persistence",
            tags=["wmi", "persistence"],
            patterns=[
                r'Set-WmiInstance.*__EventFilter',
                r'ActiveScriptEventConsumer',
                r'__EventFilter',
                r'__FilterToConsumerBinding',
                r'CommandLineEventConsumer',
            ],
        ),
        Rule(
            name="scheduled_task_creation",
            technique_id="SCHTASK_CREATE",
            mitre_id="T1053.005",
            severity=55,
            description="Scheduled task creation for persistence",
            tags=["schtask", "persistence"],
            patterns=[
                r'Register-ScheduledTask',
                r'New-ScheduledTaskAction',
                r'schtasks\s*/create',
                r'SchTasks\.exe.*\/create',
            ],
        ),
        Rule(
            name="encoded_command",
            technique_id="ENCODED_CMD",
            mitre_id="T1059.001",
            severity=50,
            description="Encoded command execution flag",
            tags=["encoded", "obfuscation"],
            patterns=[
                r'-EncodedCommand\s+[A-Za-z0-9+/]{20,}',
                r'(?:-enc|-e)\s+[A-Za-z0-9+/]{20,}',
                r'-ec\s+[A-Za-z0-9+/]{20,}',
            ],
        ),
        Rule(
            name="etw_bypass",
            technique_id="ETW_BYPASS",
            mitre_id="T1562.006",
            severity=80,
            description="Event Tracing for Windows bypass",
            tags=["etw", "bypass", "evasion"],
            patterns=[
                r'EtwEventWrite',
                r'ntdll.*EtwEventWrite',
                r'PatchEtw',
                r'EtwEventWriteFull',
            ],
        ),
        Rule(
            name="defender_exclusion",
            technique_id="AV_EXCLUSION",
            mitre_id="T1562.001",
            severity=75,
            description="Defender exclusion or disabling realtime protection",
            tags=["defender", "exclusion", "evasion"],
            patterns=[
                r'Add-MpPreference\s+-ExclusionPath',
                r'Add-MpPreference\s+-ExclusionExtension',
                r'Set-MpPreference\s+-DisableRealtimeMonitoring',
                r'Set-MpPreference\s+-DisableIOAVProtection',
                r'DisableAntiSpyware',
            ],
        ),
        Rule(
            name="registry_run_persistence",
            technique_id="REG_PERSIST",
            mitre_id="T1547.001",
            severity=55,
            description="Registry Run key persistence",
            tags=["registry", "persistence"],
            patterns=[
                r'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'CurrentVersion\\Run',
            ],
        ),
        Rule(
            name="reverse_shell_tcp",
            technique_id="REVERSE_SHELL",
            mitre_id="T1059.001",
            severity=95,
            description="PowerShell reverse shell via TCP socket",
            tags=["reverseshell", "c2"],
            patterns=[
                r'Net\.Sockets\.TCPClient',
                r'System\.Net\.Sockets\.TcpClient',
                r'StreamReader.*StreamWriter.*while',
                r'\$stream\.Write\(',
                r'GetStream\(\).*StreamReader',
            ],
        ),
        Rule(
            name="invoke_expression",
            technique_id="IEX_EXEC",
            mitre_id="T1059.001",
            severity=40,
            description="Invoke-Expression execution (common in loaders)",
            tags=["iex", "execution"],
            patterns=[
                r'\bInvoke-Expression\b',
                r'\bIEX\s*\(',
                r'\bIEX\s+\$',
                r'\|\s*IEX\b',
            ],
        ),
        Rule(
            name="execution_policy_bypass",
            technique_id="EXEC_POLICY_BYPASS",
            mitre_id="T1059.001",
            severity=35,
            description="Execution policy bypass flags",
            tags=["execution-policy", "bypass"],
            patterns=[
                r'-ExecutionPolicy\s+(?:Bypass|Unrestricted)',
                r'-ep\s+bypass',
                r'Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)',
            ],
        ),
        Rule(
            name="process_hollowing",
            technique_id="PROC_HOLLOW",
            mitre_id="T1055.012",
            severity=90,
            description="Process hollowing / CreateProcess + WriteProcessMemory",
            tags=["hollowing", "injection"],
            patterns=[
                r'CreateProcess.*NtUnmapViewOfSection',
                r'ZwUnmapViewOfSection',
                r'WriteProcessMemory.*SetThreadContext',
                r'ResumeThread.*shellcode',
            ],
        ),
        Rule(
            name="com_object_lateral",
            technique_id="COM_LATERAL",
            mitre_id="T1021.003",
            severity=75,
            description="COM object abuse for lateral movement",
            tags=["com", "lateral", "dcom"],
            patterns=[
                r'New-Object\s+-ComObject\s+(?:WScript\.Shell|Shell\.Application)',
                r'\[activator\]::CreateInstance',
                r'MMC20\.Application',
                r'ShellWindows',
                r'ShellBrowserWindow',
            ],
        ),
        Rule(
            name="cobalt_strike_indicators",
            technique_id="COBALT_STRIKE",
            mitre_id="T1059.001",
            severity=90,
            description="Cobalt Strike beacon / stager indicators",
            tags=["cobaltstrike", "beacon"],
            patterns=[
                r'IEX\s*\(New-Object\s+Net\.WebClient\)\.DownloadString',
                r'from_base64_string.*gzip',
                r'IO\.Compression\.GzipStream',
                r'\$DoIt\s*=',
                r'func_get_proc_address',
                r'func_get_delegate_type',
            ],
        ),
        # ── Enhanced AMSI / ETW bypasses ─────────────────────────────────────
        Rule(
            name="amsi_bypass_patch",
            technique_id="AMSI_BYPASS_PATCH",
            mitre_id="T1562.001",
            severity=95,
            description="AMSI bypass via direct memory patching (WriteProcessMemory / VirtualProtect on amsi.dll)",
            tags=["amsi", "bypass", "patch", "memory"],
            patterns=[
                r'VirtualProtect.*amsi',
                r'WriteProcessMemory.*amsi',
                r'\[Byte\[\]\]\s*\(0xB8,\s*0x57',     # common patch bytes
                r'AmsiScanBuffer.*0x',
                r'kernel32.*VirtualProtect.*amsiInitFailed',
                r'Marshal\.Copy.*amsi',
            ],
        ),
        Rule(
            name="amsi_force_disable",
            technique_id="AMSI_FORCE_DISABLE",
            mitre_id="T1562.001",
            severity=85,
            description="AMSI forcibly disabled via registry or policy key",
            tags=["amsi", "bypass", "registry"],
            patterns=[
                r'HKLM:\\SOFTWARE\\Microsoft\\Windows Script\\Settings.*AmsiEnable',
                r'Set-ItemProperty.*AmsiEnable.*0',
                r'reg\s+add.*AmsiEnable.*\/d\s+0',
                r'DisableAntiMalware',
                r'HKLM:.*ScriptScan.*Disable',
            ],
        ),
        Rule(
            name="etw_patch_inline",
            technique_id="ETW_PATCH_INLINE",
            mitre_id="T1562.006",
            severity=90,
            description="ETW disabled via inline patching of EtwEventWrite in ntdll",
            tags=["etw", "bypass", "patch", "ntdll"],
            patterns=[
                r'ntdll.*EtwEventWrite',
                r'GetProcAddress.*EtwEventWrite',
                r'\[Byte\[\]\]\s*\(0xC3\)',             # RET opcode patch
                r'VirtualProtect.*ntdll',
                r'Marshal\.Copy.*ntdll',
                r'EtwEventWriteTransfer',
            ],
        ),
        Rule(
            name="etw_provider_disable",
            technique_id="ETW_PROVIDER_DISABLE",
            mitre_id="T1562.006",
            severity=75,
            description="ETW provider disabled or AutoLogger registry tampered",
            tags=["etw", "bypass", "registry", "autologger"],
            patterns=[
                r'AutoLogger-Diagtrack',
                r'reg\s+delete.*AutoLogger',
                r'Set-ItemProperty.*Start.*0x4.*AutoLogger',
                r'EventLog.*Set-Service.*Disabled',
                r'wevtutil\s+sl\s+.*\/e:false',
            ],
        ),
        # ── LOLBin chaining ──────────────────────────────────────────────────
        Rule(
            name="lolbin_certutil",
            technique_id="LOLBIN_CERTUTIL",
            mitre_id="T1140",
            severity=75,
            description="certutil abused for payload download or decode",
            tags=["lolbin", "certutil", "download"],
            patterns=[
                r'certutil\s+.*-decode',
                r'certutil\s+.*-decodehex',
                r'certutil\s+.*-urlcache\s+.*-split\s+.*-f',
                r'certutil\.exe.*-decode',
                r'certutil.*http[s]?://',
            ],
        ),
        Rule(
            name="lolbin_mshta",
            technique_id="LOLBIN_MSHTA",
            mitre_id="T1218.005",
            severity=80,
            description="mshta.exe abused to execute script via HTA file or VBScript",
            tags=["lolbin", "mshta", "execution"],
            patterns=[
                r'mshta\s+https?://',
                r'mshta\.exe\s+.*vbscript:',
                r'mshta\.exe\s+.*javascript:',
                r'Start-Process\s+mshta',
                r'shell\.run.*mshta',
            ],
        ),
        Rule(
            name="lolbin_regsvr32",
            technique_id="LOLBIN_REGSVR32",
            mitre_id="T1218.010",
            severity=80,
            description="regsvr32 squiblydoo technique for proxy execution",
            tags=["lolbin", "regsvr32", "squiblydoo"],
            patterns=[
                r'regsvr32\s+.*\/s\s+.*\/n\s+.*\/i:http',
                r'regsvr32\.exe.*scrobj\.dll',
                r'regsvr32\s+\/u\s+.*\/s\s+.*\/i:',
                r'Start-Process\s+regsvr32.*scrobj',
            ],
        ),
        Rule(
            name="lolbin_rundll32",
            technique_id="LOLBIN_RUNDLL32",
            mitre_id="T1218.011",
            severity=75,
            description="rundll32 proxy execution via javascript or URL",
            tags=["lolbin", "rundll32"],
            patterns=[
                r'rundll32\s+.*javascript:',
                r'rundll32\.exe\s+.*,\s*Control_RunDLL',
                r'rundll32\s+shell32\.dll,ShellExec_RunDLL',
                r'rundll32.*url\.dll.*FileProtocolHandler.*http',
                r'Start-Process\s+rundll32',
            ],
        ),
        Rule(
            name="lolbin_bitsadmin",
            technique_id="LOLBIN_BITSADMIN",
            mitre_id="T1197",
            severity=70,
            description="bitsadmin used for file download and persistence",
            tags=["lolbin", "bitsadmin", "download"],
            patterns=[
                r'bitsadmin\s+\/transfer',
                r'bitsadmin\s+\/addfile',
                r'bitsadmin\s+\/setnotifycmdline',
                r'bitsadmin\.exe.*http[s]?://',
            ],
        ),
        Rule(
            name="wmic_remote_exec",
            technique_id="WMIC_REMOTE_EXEC",
            mitre_id="T1047",
            severity=80,
            description="WMIC used for remote command execution or process creation",
            tags=["wmic", "lateral", "wmi"],
            patterns=[
                r'wmic\s+\/node:',
                r'wmic\s+.*process\s+call\s+create',
                r'wmic\.exe.*\/node:.*call\s+create',
                r'Invoke-WmiMethod.*-ComputerName',
                r'Win32_Process.*Create.*ComputerName',
            ],
        ),
        # ── Credential access enrichment ─────────────────────────────────────
        Rule(
            name="kerberoast_spn",
            technique_id="KERBEROAST_SPN",
            mitre_id="T1558.003",
            severity=85,
            description="Kerberoasting — requesting TGS tickets for SPNs",
            tags=["kerberos", "kerberoast", "credential"],
            patterns=[
                r'GetRequest.*KerberosRequestorSecurityToken',
                r'Request-SPNTicket',
                r'Invoke-Kerberoast',
                r'[Ss]ystem\.IdentityModel\.Tokens\.KerberosRequestorSecurityToken',
                r'setspn\s+-[Tt]',
                r'Get-DomainSPNTicket',
            ],
        ),
        Rule(
            name="asreproast",
            technique_id="ASREPROAST",
            mitre_id="T1558.004",
            severity=85,
            description="AS-REP Roasting — requesting AS-REP for accounts without pre-auth",
            tags=["kerberos", "asreproast", "credential"],
            patterns=[
                r'Invoke-ASREPRoast',
                r'Get-ASREPHash',
                r'DoesNotRequirePreAuth',
                r'DONT_REQ_PREAUTH',
                r'Get-DomainUser.*-PreauthNotRequired',
            ],
        ),
        Rule(
            name="dpapi_decrypt",
            technique_id="DPAPI_DECRYPT",
            mitre_id="T1555",
            severity=80,
            description="DPAPI master key or credential blob decryption",
            tags=["dpapi", "credential", "decrypt"],
            patterns=[
                r'dpapi::',
                r'Get-DPAPIMasterKey',
                r'Invoke-DPAPIDump',
                r'CryptUnprotectData',
                r'ProtectedData\.Unprotect',
                r'DPAPI.*MasterKey',
            ],
        ),
        Rule(
            name="sam_dump",
            technique_id="SAM_DUMP",
            mitre_id="T1003.002",
            severity=90,
            description="SAM database dump for local credential extraction",
            tags=["sam", "credential", "dump"],
            patterns=[
                r'reg\s+save.*HKLM\\SAM',
                r'reg\s+save.*HKLM\\SYSTEM',
                r'lsadump::sam',
                r'secretsdump',
                r'Invoke-NinjaCopy.*sam',
                r'shadow\s+copy.*sam',
                r'vssadmin.*create.*shadow',
            ],
        ),
        Rule(
            name="dcsync_pattern",
            technique_id="DCSYNC_PATTERN",
            mitre_id="T1003.006",
            severity=95,
            description="DCSync attack — replicating domain credentials from DC",
            tags=["dcsync", "credential", "domain"],
            patterns=[
                r'lsadump::dcsync',
                r'Invoke-DCSync',
                r'DrsGetNCChanges',
                r'DS-Replication-Get-Changes',
                r'replicatechanges',
                r'drsuapi',
            ],
        ),
        Rule(
            name="lsass_read",
            technique_id="LSASS_READ",
            mitre_id="T1003.001",
            severity=90,
            description="LSASS memory read for credential extraction",
            tags=["lsass", "credential", "memory"],
            patterns=[
                r'OpenProcess.*lsass',
                r'ReadProcessMemory.*lsass',
                r'MiniDumpWriteDump.*lsass',
                r'procdump.*lsass',
                r'comsvcs\.dll.*MiniDump',
                r'Out-Minidump',
                r'Invoke-Mimikatz.*lsass',
            ],
        ),
        # ── Lateral movement ─────────────────────────────────────────────────
        Rule(
            name="lateral_psremoting",
            technique_id="LATERAL_PSREMOTING",
            mitre_id="T1021.006",
            severity=80,
            description="WinRM / PSRemoting used for lateral movement",
            tags=["lateral", "psremoting", "winrm"],
            patterns=[
                r'Invoke-Command\s+.*-ComputerName',
                r'New-PSSession\s+.*-ComputerName',
                r'Enter-PSSession\s+.*-ComputerName',
                r'Invoke-Command\s+.*-Session\s+\$',
                r'New-CimSession\s+.*-ComputerName',
            ],
        ),
        Rule(
            name="lateral_invoke_cmd",
            technique_id="LATERAL_INVOKE_CMD",
            mitre_id="T1021.002",
            severity=75,
            description="Remote command execution via SMB / admin shares",
            tags=["lateral", "smb", "psexec"],
            patterns=[
                r'\\\\[^\\]+\\[Aa]dmin\$',
                r'\\\\[^\\]+\\C\$\\',
                r'psexec\s+\\\\',
                r'sc\s+\\\\.*create',
                r'net\s+use\s+\\\\',
            ],
        ),
        Rule(
            name="lateral_wmi_exec",
            technique_id="LATERAL_WMI_EXEC",
            mitre_id="T1021.003",
            severity=80,
            description="WMI used for remote code execution on lateral targets",
            tags=["lateral", "wmi", "dcom"],
            patterns=[
                r'Invoke-WMIMethod\s+.*-ComputerName',
                r'Get-WMIObject\s+.*-ComputerName',
                r'[Ww][Mm][Ii]\s+.*-ComputerName',
                r'Win32_Process\.Create.*namespace.*\\\\',
                r'\$wmi\s*=.*ConnectServer',
            ],
        ),
        # ── Process injection / additional injection patterns ─────────────────
        Rule(
            name="process_injection_openprocess",
            technique_id="PROC_INJECT_OPENPROC",
            mitre_id="T1055",
            severity=90,
            description="Process injection via OpenProcess + VirtualAllocEx + WriteProcessMemory",
            tags=["injection", "openprocess"],
            patterns=[
                r'OpenProcess\s*\(',
                r'VirtualAllocEx\s*\(',
                r'WriteProcessMemory\s*\(',
                r'CreateRemoteThread\s*\(',
                r'QueueUserAPC\s*\(',
            ],
        ),
        Rule(
            name="scheduled_task_hijack",
            technique_id="SCHTASK_HIJACK",
            mitre_id="T1053.005",
            severity=75,
            description="Scheduled task binary hijacking or path manipulation",
            tags=["schtask", "hijack", "persistence"],
            patterns=[
                r'schtasks.*\/change.*\/TR',
                r'Set-ScheduledTask.*-Execute',
                r'[Ss]cheduled[Tt]ask.*\.Actions\.Add',
                r'SchTasks.*\/F.*\/SC',
            ],
        ),
    ]


# ── Classifier ────────────────────────────────────────────────────────────────

class Classifier:
    """Applies all loaded rules to a ScriptBlock and populates its findings."""

    def __init__(self, rules: Optional[list[Rule]] = None):
        self.rules = rules if rules is not None else load_rules()
        log.info("Classifier initialised with %d rules", len(self.rules))

    def classify(self, block: ScriptBlock) -> ScriptBlock:
        """
        Run all rules against block.decoded_text.
        Populates block.findings in place and returns the block.
        """
        text = block.decoded_text or block.raw_text

        for rule in self.rules:
            hits = rule.match(text)
            for matched_text, context in hits:
                block.findings.append(Finding(
                    technique_id=rule.technique_id,
                    mitre_id=rule.mitre_id,
                    severity=rule.severity,
                    rule_name=rule.name,
                    matched_text=matched_text,
                    context=context,
                ))

        # Entropy-only finding: no rule fired but block looks heavily encoded
        if not block.findings and block.entropy > 6.0 and len(text) > 300:
            block.findings.append(Finding(
                technique_id="HIGH_ENTROPY_BLOB",
                mitre_id="T1059.001",
                severity=40,
                rule_name="entropy_heuristic",
                matched_text=f"entropy={block.entropy:.2f}",
                context=text[:80],
                confidence=0.5,
            ))

        return block

    def classify_batch(self, blocks: list[ScriptBlock]) -> list[ScriptBlock]:
        return [self.classify(b) for b in blocks]
