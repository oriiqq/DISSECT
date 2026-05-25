"""
ps_classifier — SIEM detection query generator

Generates ready-to-run detection queries for:
  - Microsoft Sentinel  (KQL / Kusto)
  - Splunk              (SPL)
  - IBM QRadar          (AQL)
  - Elastic Security    (EQL)
  - Google Chronicle    (YARA-L 2.0)

All queries target Event ID 4104 — PowerShell Script Block Logging.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from core.models import Session, Finding


def _det_severity(severity: int) -> str:
    if severity >= 85: return "critical"
    if severity >= 70: return "high"
    if severity >= 50: return "medium"
    return "low"

def _yaral_severity(severity: int) -> str:
    if severity >= 85: return "CRITICAL"
    if severity >= 70: return "HIGH"
    if severity >= 50: return "MEDIUM"
    return "LOW"


# ── Per-technique query templates ──────────────────────────────────────────────
_TEMPLATES: dict[str, dict] = {

    "AMSI_BYPASS_REFLECT": {
        "title": "AMSI Bypass via .NET Reflection",
        "mitre": "T1562.001",
        "kql": (
            "// AMSI bypass via .NET reflection  —  T1562.001\n"
            "// Covers: amsiInitFailed patching, AmsiScanBuffer reflection\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"amsiInitFailed\", \"AmsiScanBuffer\")\n"
            "      or (EventData has \"GetField\" and EventData has \"amsi\")\n"
            "| extend Hostname = tostring(split(Computer, \".\")[0])\n"
            "| extend Severity = \"High\", Technique = \"AMSI_BYPASS_REFLECT\"\n"
            "| project TimeGenerated, Hostname, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"AMSI bypass via .NET reflection — T1562.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*amsiInitFailed*\" OR Message=\"*AmsiScanBuffer*\"\n"
            "     OR (Message=\"*GetField*\" AND Message=\"*amsi*\"))\n"
            "| eval Severity=\"High\", Technique=\"AMSI_BYPASS_REFLECT\", MITRE=\"T1562.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- AMSI bypass via .NET reflection  —  T1562.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%amsiInitFailed%'\n"
            "    OR UTF8(payload) ILIKE '%AmsiScanBuffer%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// AMSI bypass via .NET reflection  —  T1562.001\n"
            "// Elastic Security — index: winlogbeat-* or logs-windows.*\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*amsiInitFailed*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*AmsiScanBuffer*\" or\n"
            "    (\n"
            "      winlog.event_data.ScriptBlockText like~ \"*GetField*\" and\n"
            "      winlog.event_data.ScriptBlockText like~ \"*amsi*\"\n"
            "    )\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_amsi_bypass_reflect {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"PowerShell AMSI bypass via .NET reflection\"\n"
            "    severity        = \"HIGH\"\n"
            "    mitre_technique = \"T1562.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `amsiInitFailed`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `AmsiScanBuffer`) nocase\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "AMSI_BYPASS_COM": {
        "title": "AMSI Bypass via COM Object",
        "mitre": "T1562.001",
        "kql": (
            "// AMSI bypass via COM object  —  T1562.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"IAmsiStream\", \"AmsiInitialize\", \"amsi.AMSI\")\n"
            "| extend Severity = \"High\", Technique = \"AMSI_BYPASS_COM\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"AMSI bypass via COM — T1562.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*IAmsiStream*\" OR Message=\"*AmsiInitialize*\"\n"
            "     OR Message=\"*amsi.AMSI*\")\n"
            "| eval Severity=\"High\", Technique=\"AMSI_BYPASS_COM\", MITRE=\"T1562.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- AMSI bypass via COM  —  T1562.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%IAmsiStream%'\n"
            "    OR UTF8(payload) ILIKE '%AmsiInitialize%'\n"
            "    OR UTF8(payload) ILIKE '%amsi.AMSI%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// AMSI bypass via COM object  —  T1562.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*IAmsiStream*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*AmsiInitialize*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*amsi.AMSI*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_amsi_bypass_com {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"PowerShell AMSI bypass via COM object\"\n"
            "    severity        = \"HIGH\"\n"
            "    mitre_technique = \"T1562.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `IAmsiStream`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `AmsiInitialize`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `amsi\\.AMSI`) nocase\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "DOWNLOAD_CRADLE_WC": {
        "title": "Download Cradle via Net.WebClient",
        "mitre": "T1105",
        "kql": (
            "// PowerShell download cradle — Net.WebClient + IEX  —  T1105\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where (EventData has \"Net.WebClient\"\n"
            "     and EventData has_any (\"DownloadString\",\"DownloadFile\",\"DownloadData\"))\n"
            "   or  (EventData has \"Net.WebClient\"\n"
            "     and EventData has_any (\"IEX\",\"Invoke-Expression\"))\n"
            "| extend Severity = \"High\", Technique = \"DOWNLOAD_CRADLE_WC\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"Download cradle — Net.WebClient  —  T1105\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    Message=\"*Net.WebClient*\"\n"
            "    (Message=\"*DownloadString*\" OR Message=\"*DownloadFile*\"\n"
            "     OR Message=\"*DownloadData*\" OR Message=\"*IEX*\"\n"
            "     OR Message=\"*Invoke-Expression*\")\n"
            "| eval Severity=\"High\", Technique=\"DOWNLOAD_CRADLE_WC\", MITRE=\"T1105\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- PowerShell download cradle — Net.WebClient  —  T1105\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND UTF8(payload) ILIKE '%Net.WebClient%'\n"
            "  AND (UTF8(payload) ILIKE '%DownloadString%'\n"
            "    OR UTF8(payload) ILIKE '%DownloadFile%'\n"
            "    OR UTF8(payload) ILIKE '%IEX%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// Download cradle via Net.WebClient  —  T1105\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and winlog.event_data.ScriptBlockText like~ \"*Net.WebClient*\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*DownloadString*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*DownloadFile*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*DownloadData*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*IEX*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_download_cradle_wc {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"PowerShell download cradle via Net.WebClient\"\n"
            "    severity        = \"HIGH\"\n"
            "    mitre_technique = \"T1105\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    re.regex($e.principal.process.command_line, `Net\\.WebClient`) nocase\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `DownloadString`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `DownloadFile`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `IEX`) or\n"
            "      re.regex($e.principal.process.command_line, `Invoke-Expression`) nocase\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "DOWNLOAD_CRADLE_BITS": {
        "title": "Download Cradle via BITS Transfer",
        "mitre": "T1197",
        "kql": (
            "// PowerShell BITS download cradle  —  T1197\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"Start-BitsTransfer\", \"BitsTransfer\")\n"
            "| extend Severity = \"Medium\", Technique = \"DOWNLOAD_CRADLE_BITS\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"BITS download cradle  —  T1197\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*Start-BitsTransfer*\" OR Message=\"*BitsTransfer*\")\n"
            "| eval Severity=\"Medium\", Technique=\"DOWNLOAD_CRADLE_BITS\", MITRE=\"T1197\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- BITS download cradle  —  T1197\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%Start-BitsTransfer%'\n"
            "    OR UTF8(payload) ILIKE '%BitsTransfer%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// BITS download cradle  —  T1197\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*Start-BitsTransfer*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*BitsTransfer*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_download_cradle_bits {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"PowerShell BITS-based download cradle\"\n"
            "    severity        = \"MEDIUM\"\n"
            "    mitre_technique = \"T1197\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `Start-BitsTransfer`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `BitsTransfer`) nocase\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "REFLECTIVE_INJECT": {
        "title": "Reflective PE / DLL Injection",
        "mitre": "T1055.001",
        "kql": (
            "// Reflective PE/DLL injection via PowerShell  —  T1055.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"Invoke-ReflectivePEInjection\",\n"
            "                           \"Invoke-ReflectiveDllInjection\")\n"
            "   or  (EventData has \"VirtualAlloc\"\n"
            "    and EventData has \"WriteProcessMemory\")\n"
            "| extend Severity = \"Critical\", Technique = \"REFLECTIVE_INJECT\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"Reflective PE/DLL injection  —  T1055.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*Invoke-ReflectivePEInjection*\"\n"
            "     OR Message=\"*Invoke-ReflectiveDllInjection*\"\n"
            "     OR (Message=\"*VirtualAlloc*\" AND Message=\"*WriteProcessMemory*\"))\n"
            "| eval Severity=\"Critical\", Technique=\"REFLECTIVE_INJECT\", MITRE=\"T1055.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- Reflective PE/DLL injection  —  T1055.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%Invoke-ReflectivePEInjection%'\n"
            "    OR UTF8(payload) ILIKE '%Invoke-ReflectiveDllInjection%'\n"
            "    OR (UTF8(payload) ILIKE '%VirtualAlloc%'\n"
            "   AND UTF8(payload) ILIKE '%WriteProcessMemory%'))\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// Reflective PE/DLL injection  —  T1055.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*Invoke-ReflectivePEInjection*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*Invoke-ReflectiveDllInjection*\" or\n"
            "    (\n"
            "      winlog.event_data.ScriptBlockText like~ \"*VirtualAlloc*\" and\n"
            "      winlog.event_data.ScriptBlockText like~ \"*WriteProcessMemory*\"\n"
            "    )\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_reflective_inject {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"PowerShell reflective PE/DLL injection\"\n"
            "    severity        = \"CRITICAL\"\n"
            "    mitre_technique = \"T1055.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `Invoke-ReflectivePEInjection`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `Invoke-ReflectiveDllInjection`) nocase or\n"
            "      (\n"
            "        re.regex($e.principal.process.command_line, `VirtualAlloc`) nocase and\n"
            "        re.regex($e.principal.process.command_line, `WriteProcessMemory`) nocase\n"
            "      )\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "SHELLCODE_MARSHAL": {
        "title": "Shellcode via InteropServices.Marshal",
        "mitre": "T1055",
        "kql": (
            "// Shellcode via Runtime.InteropServices.Marshal  —  T1055\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has \"AllocHGlobal\"\n"
            "     and EventData has \"GetDelegateForFunctionPointer\"\n"
            "| extend Severity = \"Critical\", Technique = \"SHELLCODE_MARSHAL\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"Shellcode via Marshal  —  T1055\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    Message=\"*AllocHGlobal*\" Message=\"*GetDelegateForFunctionPointer*\"\n"
            "| eval Severity=\"Critical\", Technique=\"SHELLCODE_MARSHAL\", MITRE=\"T1055\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- Shellcode via Marshal  —  T1055\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND UTF8(payload) ILIKE '%AllocHGlobal%'\n"
            "  AND UTF8(payload) ILIKE '%GetDelegateForFunctionPointer%'\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// Shellcode via InteropServices.Marshal  —  T1055\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and winlog.event_data.ScriptBlockText like~ \"*AllocHGlobal*\"\n"
            "  and winlog.event_data.ScriptBlockText like~ \"*GetDelegateForFunctionPointer*\""
        ),
        "yaral": (
            "rule ps_classifier_shellcode_marshal {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"Shellcode execution via Runtime.InteropServices.Marshal\"\n"
            "    severity        = \"CRITICAL\"\n"
            "    mitre_technique = \"T1055\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    re.regex($e.principal.process.command_line, `AllocHGlobal`) nocase\n"
            "    re.regex($e.principal.process.command_line, `GetDelegateForFunctionPointer`) nocase\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "CRED_HARVEST": {
        "title": "Credential Harvesting (Mimikatz)",
        "mitre": "T1003.001",
        "kql": (
            "// Mimikatz / credential harvesting via PowerShell  —  T1003.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"sekurlsa\", \"Invoke-Mimikatz\",\n"
            "                           \"DumpCreds\", \"lsadump::\", \"kerberos::\")\n"
            "| extend Severity = \"Critical\", Technique = \"CRED_HARVEST\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"Credential harvesting — Mimikatz  —  T1003.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*sekurlsa*\" OR Message=\"*Invoke-Mimikatz*\"\n"
            "     OR Message=\"*DumpCreds*\" OR Message=\"*lsadump::*\"\n"
            "     OR Message=\"*kerberos::*\")\n"
            "| eval Severity=\"Critical\", Technique=\"CRED_HARVEST\", MITRE=\"T1003.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- Credential harvesting — Mimikatz  —  T1003.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%sekurlsa%'\n"
            "    OR UTF8(payload) ILIKE '%Invoke-Mimikatz%'\n"
            "    OR UTF8(payload) ILIKE '%DumpCreds%'\n"
            "    OR UTF8(payload) ILIKE '%lsadump::%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// Credential harvesting — Mimikatz  —  T1003.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*sekurlsa*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*Invoke-Mimikatz*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*DumpCreds*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*lsadump::*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*kerberos::*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_cred_harvest {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"Mimikatz-style credential harvesting via PowerShell\"\n"
            "    severity        = \"CRITICAL\"\n"
            "    mitre_technique = \"T1003.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `sekurlsa`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `Invoke-Mimikatz`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `DumpCreds`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `lsadump::`) nocase\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "WMI_PERSIST": {
        "title": "WMI Event Subscription Persistence",
        "mitre": "T1546.003",
        "kql": (
            "// WMI event subscription persistence  —  T1546.003\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"__EventFilter\",\n"
            "                           \"ActiveScriptEventConsumer\",\n"
            "                           \"__FilterToConsumerBinding\")\n"
            "| extend Severity = \"High\", Technique = \"WMI_PERSIST\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"WMI event subscription persistence  —  T1546.003\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*__EventFilter*\" OR Message=\"*ActiveScriptEventConsumer*\"\n"
            "     OR Message=\"*__FilterToConsumerBinding*\")\n"
            "| eval Severity=\"High\", Technique=\"WMI_PERSIST\", MITRE=\"T1546.003\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- WMI event subscription persistence  —  T1546.003\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%__EventFilter%'\n"
            "    OR UTF8(payload) ILIKE '%ActiveScriptEventConsumer%'\n"
            "    OR UTF8(payload) ILIKE '%__FilterToConsumerBinding%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// WMI event subscription persistence  —  T1546.003\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*__EventFilter*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*ActiveScriptEventConsumer*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*__FilterToConsumerBinding*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_wmi_persist {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"WMI permanent event subscription for persistence\"\n"
            "    severity        = \"HIGH\"\n"
            "    mitre_technique = \"T1546.003\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `__EventFilter`) or\n"
            "      re.regex($e.principal.process.command_line, `ActiveScriptEventConsumer`) or\n"
            "      re.regex($e.principal.process.command_line, `__FilterToConsumerBinding`)\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "COBALT_STRIKE": {
        "title": "Cobalt Strike Stager Indicators",
        "mitre": "T1059.001",
        "kql": (
            "// Cobalt Strike stager patterns via PowerShell  —  T1059.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where (EventData has \"IEX\" and EventData has \"Net.WebClient\"\n"
            "         and EventData has \"DownloadString\")\n"
            "   or  (EventData has \"GzipStream\"\n"
            "         and EventData has \"FromBase64String\")\n"
            "   or   EventData has \"$DoIt\"\n"
            "| extend Severity = \"Critical\", Technique = \"COBALT_STRIKE\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"Cobalt Strike stager  —  T1059.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    ((Message=\"*IEX*\" AND Message=\"*Net.WebClient*\" AND Message=\"*DownloadString*\")\n"
            "     OR (Message=\"*GzipStream*\" AND Message=\"*FromBase64String*\")\n"
            "     OR Message=\"*$DoIt*\")\n"
            "| eval Severity=\"Critical\", Technique=\"COBALT_STRIKE\", MITRE=\"T1059.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- Cobalt Strike stager  —  T1059.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND ((UTF8(payload) ILIKE '%IEX%'\n"
            "   AND UTF8(payload) ILIKE '%Net.WebClient%'\n"
            "   AND UTF8(payload) ILIKE '%DownloadString%')\n"
            "   OR (UTF8(payload) ILIKE '%GzipStream%'\n"
            "   AND UTF8(payload) ILIKE '%FromBase64String%')\n"
            "   OR UTF8(payload) ILIKE '%$DoIt%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// Cobalt Strike stager  —  T1059.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    (\n"
            "      winlog.event_data.ScriptBlockText like~ \"*IEX*\" and\n"
            "      winlog.event_data.ScriptBlockText like~ \"*Net.WebClient*\" and\n"
            "      winlog.event_data.ScriptBlockText like~ \"*DownloadString*\"\n"
            "    ) or (\n"
            "      winlog.event_data.ScriptBlockText like~ \"*GzipStream*\" and\n"
            "      winlog.event_data.ScriptBlockText like~ \"*FromBase64String*\"\n"
            "    ) or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*$DoIt*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_cobalt_strike {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"Cobalt Strike stager delivery patterns\"\n"
            "    severity        = \"CRITICAL\"\n"
            "    mitre_technique = \"T1059.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      (\n"
            "        re.regex($e.principal.process.command_line, `IEX`) and\n"
            "        re.regex($e.principal.process.command_line, `Net\\.WebClient`) nocase and\n"
            "        re.regex($e.principal.process.command_line, `DownloadString`) nocase\n"
            "      ) or (\n"
            "        re.regex($e.principal.process.command_line, `GzipStream`) nocase and\n"
            "        re.regex($e.principal.process.command_line, `FromBase64String`) nocase\n"
            "      ) or\n"
            "      re.regex($e.principal.process.command_line, `\\$DoIt`)\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "REVERSE_SHELL": {
        "title": "TCP Reverse Shell",
        "mitre": "T1059.001",
        "kql": (
            "// PowerShell TCP reverse shell  —  T1059.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"Net.Sockets.TcpClient\",\n"
            "                           \"System.Net.Sockets.TcpClient\")\n"
            "   or  (EventData has \"GetStream\"\n"
            "    and EventData has \"StreamReader\")\n"
            "| extend Severity = \"Critical\", Technique = \"REVERSE_SHELL\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"TCP reverse shell  —  T1059.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*Net.Sockets.TcpClient*\"\n"
            "     OR Message=\"*System.Net.Sockets.TcpClient*\"\n"
            "     OR (Message=\"*GetStream*\" AND Message=\"*StreamReader*\"))\n"
            "| eval Severity=\"Critical\", Technique=\"REVERSE_SHELL\", MITRE=\"T1059.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- TCP reverse shell  —  T1059.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%Net.Sockets.TcpClient%'\n"
            "    OR (UTF8(payload) ILIKE '%GetStream%'\n"
            "   AND UTF8(payload) ILIKE '%StreamReader%'))\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// TCP reverse shell  —  T1059.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*Net.Sockets.TcpClient*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*System.Net.Sockets.TcpClient*\" or\n"
            "    (\n"
            "      winlog.event_data.ScriptBlockText like~ \"*GetStream*\" and\n"
            "      winlog.event_data.ScriptBlockText like~ \"*StreamReader*\"\n"
            "    )\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_reverse_shell {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"PowerShell TCP reverse shell\"\n"
            "    severity        = \"CRITICAL\"\n"
            "    mitre_technique = \"T1059.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `Net\\.Sockets\\.TcpClient`) nocase or\n"
            "      (\n"
            "        re.regex($e.principal.process.command_line, `GetStream`) nocase and\n"
            "        re.regex($e.principal.process.command_line, `StreamReader`) nocase\n"
            "      )\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "ETW_BYPASS": {
        "title": "ETW Event Tracing Bypass",
        "mitre": "T1562.006",
        "kql": (
            "// ETW bypass via EtwEventWrite patching  —  T1562.006\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"EtwEventWrite\", \"PatchEtw\", \"EtwEventWriteFull\")\n"
            "| extend Severity = \"High\", Technique = \"ETW_BYPASS\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"ETW bypass  —  T1562.006\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*EtwEventWrite*\" OR Message=\"*PatchEtw*\"\n"
            "     OR Message=\"*EtwEventWriteFull*\")\n"
            "| eval Severity=\"High\", Technique=\"ETW_BYPASS\", MITRE=\"T1562.006\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- ETW bypass  —  T1562.006\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%EtwEventWrite%'\n"
            "    OR UTF8(payload) ILIKE '%PatchEtw%'\n"
            "    OR UTF8(payload) ILIKE '%EtwEventWriteFull%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// ETW bypass  —  T1562.006\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*EtwEventWrite*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*PatchEtw*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*EtwEventWriteFull*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_etw_bypass {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"ETW event tracing bypass via EtwEventWrite patching\"\n"
            "    severity        = \"HIGH\"\n"
            "    mitre_technique = \"T1562.006\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `EtwEventWrite`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `PatchEtw`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `EtwEventWriteFull`) nocase\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "AV_EXCLUSION": {
        "title": "Defender Exclusion / Disable",
        "mitre": "T1562.001",
        "kql": (
            "// Windows Defender exclusion or disable  —  T1562.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData has_any (\"Add-MpPreference -ExclusionPath\",\n"
            "                           \"Set-MpPreference -DisableRealtimeMonitoring\",\n"
            "                           \"DisableAntiSpyware\")\n"
            "| extend Severity = \"High\", Technique = \"AV_EXCLUSION\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"Defender exclusion/disable  —  T1562.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*Add-MpPreference*ExclusionPath*\"\n"
            "     OR Message=\"*Set-MpPreference*DisableRealtimeMonitoring*\"\n"
            "     OR Message=\"*DisableAntiSpyware*\")\n"
            "| eval Severity=\"High\", Technique=\"AV_EXCLUSION\", MITRE=\"T1562.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- Defender exclusion/disable  —  T1562.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%Add-MpPreference%ExclusionPath%'\n"
            "    OR UTF8(payload) ILIKE '%DisableRealtimeMonitoring%'\n"
            "    OR UTF8(payload) ILIKE '%DisableAntiSpyware%')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// Defender exclusion or disable  —  T1562.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*Add-MpPreference*ExclusionPath*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*DisableRealtimeMonitoring*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*DisableAntiSpyware*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_av_exclusion {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"Windows Defender exclusion or disabling\"\n"
            "    severity        = \"HIGH\"\n"
            "    mitre_technique = \"T1562.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    (\n"
            "      re.regex($e.principal.process.command_line, `Add-MpPreference`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `DisableRealtimeMonitoring`) nocase or\n"
            "      re.regex($e.principal.process.command_line, `DisableAntiSpyware`) nocase\n"
            "    )\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "ENCODED_CMD": {
        "title": "Encoded Command Execution",
        "mitre": "T1059.001",
        "kql": (
            "// PowerShell -EncodedCommand obfuscated execution  —  T1059.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData matches regex @\"-E(nc(odedCommand)?|C)\\s+[A-Za-z0-9+/]{20,}\"\n"
            "| extend Severity = \"Medium\", Technique = \"ENCODED_CMD\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"Encoded command execution  —  T1059.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "    (Message=\"*-EncodedCommand*\" OR Message=\"*-Enc *\" OR Message=\"*-EC *\")\n"
            "| eval Severity=\"Medium\", Technique=\"ENCODED_CMD\", MITRE=\"T1059.001\"\n"
            "| table _time, host, user, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- Encoded command execution  —  T1059.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND (UTF8(payload) ILIKE '%-EncodedCommand%'\n"
            "    OR UTF8(payload) ILIKE '%-Enc %'\n"
            "    OR UTF8(payload) ILIKE '%-EC %')\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// Encoded command execution  —  T1059.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*-EncodedCommand*\" or\n"
            "    winlog.event_data.ScriptBlockText regex \"-E(nc|C)\\\\s+[A-Za-z0-9+/]{20,}\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_encoded_cmd {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"PowerShell -EncodedCommand obfuscated execution\"\n"
            "    severity        = \"MEDIUM\"\n"
            "    mitre_technique = \"T1059.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    re.regex($e.principal.process.command_line,\n"
            "      `-E(nc(odedCommand)?|C)\\s+[A-Za-z0-9+/]{20,}`) nocase\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },

    "HIGH_ENTROPY_BLOB": {
        "title": "High-Entropy Base64 Payload Blob",
        "mitre": "T1059.001",
        "kql": (
            "// High-entropy Base64 blob (potential encoded payload)  —  T1059.001\n"
            "Event\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where EventID == 4104\n"
            "| where EventData matches regex @\"[A-Za-z0-9+/]{200,}={0,2}\"\n"
            "| where not (EventData has_any (\"# Copyright\", \"param(\", \"function \"))\n"
            "| extend Severity = \"Medium\", Technique = \"HIGH_ENTROPY_BLOB\"\n"
            "| project TimeGenerated, Computer, UserName, EventData, Severity, Technique\n"
            "| order by TimeGenerated desc"
        ),
        "spl": (
            "| comment \"High-entropy Base64 payload blob  —  T1059.001\"\n"
            "index=wineventlog EventCode=4104 earliest=-7d\n"
            "| rex field=Message \"(?P<b64>[A-Za-z0-9+/]{200,}={0,2})\"\n"
            "| where isnotnull(b64)\n"
            "    AND NOT (match(Message, \"# Copyright|param\\(|function \"))\n"
            "| eval Severity=\"Medium\", Technique=\"HIGH_ENTROPY_BLOB\", MITRE=\"T1059.001\"\n"
            "| table _time, host, user, b64, Message, Severity, Technique, MITRE\n"
            "| sort -_time"
        ),
        "aql": (
            "-- High-entropy Base64 payload blob  —  T1059.001\n"
            "SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            "       sourceip AS \"Source\", username AS \"User\",\n"
            "       UTF8(payload) AS \"Script Block\"\n"
            "FROM events\n"
            "WHERE devicetype = 12 AND eventid = 4104\n"
            "  AND UTF8(payload) MATCHES REGEX '[A-Za-z0-9+/]{200,}={0,2}'\n"
            "  AND UTF8(payload) NOT ILIKE '%# Copyright%'\n"
            "LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            "// High-entropy Base64 payload blob  —  T1059.001\n"
            "any where event.code == \"4104\"\n"
            "  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            "  and winlog.event_data.ScriptBlockText regex \"[A-Za-z0-9+/]{200,}={0,2}\"\n"
            "  and not (\n"
            "    winlog.event_data.ScriptBlockText like~ \"*# Copyright*\" or\n"
            "    winlog.event_data.ScriptBlockText like~ \"*param(*\"\n"
            "  )"
        ),
        "yaral": (
            "rule ps_classifier_high_entropy_blob {\n"
            "  meta:\n"
            "    author          = \"ps_classifier\"\n"
            "    description     = \"High-entropy Base64 blob — possible encoded payload\"\n"
            "    severity        = \"MEDIUM\"\n"
            "    mitre_technique = \"T1059.001\"\n"
            "  events:\n"
            "    $e.metadata.product_event_type = \"4104\"\n"
            "    re.regex($e.principal.process.command_line,\n"
            "      `[A-Za-z0-9+/]{200,}={0,2}`)\n"
            "    not re.regex($e.principal.process.command_line,\n"
            "      `# Copyright|param\\(|^function `)\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    },
}


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class Detection:
    technique_id: str
    title:        str
    mitre:        str
    severity:     str
    kql:          str
    spl:          str
    aql:          str
    eql:          str
    yaral:        str


@dataclass
class DetectionBundle:
    detections:   list[Detection] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    def _header(self, comment: str) -> str:
        return (
            f"{comment} ps_classifier — detection queries\n"
            f"{comment} Generated: {self.generated_at}\n"
            f"{comment} Techniques: {len(self.detections)}\n\n"
        )

    def to_kql(self) -> str:
        sep = "\n\n// " + "=" * 60 + "\n"
        return self._header("//") + sep.join(d.kql for d in self.detections)

    def to_spl(self) -> str:
        sep = "\n\n| comment \"" + "=" * 55 + "\"\n"
        return self._header("| comment \"ps_classifier\"\n") + sep.join(d.spl for d in self.detections)

    def to_aql(self) -> str:
        sep = "\n\n-- " + "=" * 60 + "\n"
        return self._header("--") + sep.join(d.aql for d in self.detections)

    def to_eql(self) -> str:
        sep = "\n\n// " + "=" * 60 + "\n"
        return self._header("//") + sep.join(d.eql for d in self.detections)

    def to_yaral(self) -> str:
        header = (
            f"// ps_classifier — Chronicle YARA-L 2.0 detection rules\n"
            f"// Generated: {self.generated_at}\n"
            f"// Rules: {len(self.detections)}\n\n"
        )
        return header + "\n\n".join(d.yaral for d in self.detections)


# ── Public generators ─────────────────────────────────────────────────────────

def generate_detections(sessions: list[Session]) -> DetectionBundle:
    """One detection per unique technique found across sessions scoring >= 40."""
    bundle = DetectionBundle()
    seen: set[str] = set()
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for session in sessions:
        if session.weighted_score < 40:
            continue
        for block in session.blocks:
            for finding in block.findings:
                tid = finding.technique_id
                if tid in seen:
                    continue
                seen.add(tid)
                tmpl = _TEMPLATES.get(tid) or _generic_template(finding)
                bundle.detections.append(Detection(
                    technique_id=tid,
                    title=tmpl["title"],
                    mitre=tmpl["mitre"],
                    severity=_det_severity(finding.severity),
                    kql=tmpl["kql"],
                    spl=tmpl["spl"],
                    aql=tmpl["aql"],
                    eql=tmpl["eql"],
                    yaral=tmpl["yaral"],
                ))

    bundle.detections.sort(key=lambda d: sev_order.get(d.severity, 4))
    return bundle


def _generic_template(finding: Finding) -> dict:
    safe  = finding.matched_text[:50].replace('"', "'")
    title = finding.technique_id.replace("_", " ").title()
    name  = "ps_classifier_" + finding.technique_id.lower()
    sev   = _yaral_severity(finding.severity)
    return {
        "title": title,
        "mitre": finding.mitre_id,
        "kql": (
            f"// {title}  —  {finding.mitre_id}\n"
            f"Event | where TimeGenerated > ago(7d)\n"
            f"| where EventID == 4104 | where EventData has \"{safe}\"\n"
            f"| project TimeGenerated, Computer, UserName, EventData | order by TimeGenerated desc"
        ),
        "spl": (
            f"| comment \"{title}  —  {finding.mitre_id}\"\n"
            f"index=wineventlog EventCode=4104 earliest=-7d Message=\"*{safe}*\"\n"
            f"| table _time, host, user, Message | sort -_time"
        ),
        "aql": (
            f"-- {title}  —  {finding.mitre_id}\n"
            f"SELECT DATEFORMAT(starttime,'dd-MM-yyyy HH:mm:ss') AS \"Time\",\n"
            f"       sourceip AS \"Source\", username AS \"User\", UTF8(payload) AS \"Script Block\"\n"
            f"FROM events WHERE devicetype=12 AND eventid=4104\n"
            f"  AND UTF8(payload) ILIKE '%{safe}%' LAST 7 DAYS ORDER BY starttime DESC"
        ),
        "eql": (
            f"// {title}  —  {finding.mitre_id}\n"
            f"any where event.code == \"4104\"\n"
            f"  and winlog.channel == \"Microsoft-Windows-PowerShell/Operational\"\n"
            f"  and winlog.event_data.ScriptBlockText like~ \"*{safe}*\""
        ),
        "yaral": (
            f"rule {name} {{\n"
            f"  meta:\n"
            f"    author = \"ps_classifier\"\n"
            f"    description = \"{title} — {finding.mitre_id}\"\n"
            f"    severity = \"{sev}\"\n"
            f"    mitre_technique = \"{finding.mitre_id}\"\n"
            f"  events:\n"
            f"    $e.metadata.product_event_type = \"4104\"\n"
            f"    re.regex($e.principal.process.command_line, `{safe}`) nocase\n"
            f"  condition:\n"
            f"    $e\n"
            f"}}"
        ),
    }
