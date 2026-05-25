"""
ps_classifier — EDR policy hardening recommendations

Generates actionable hardening guidance for:
  - CrowdStrike Falcon
  - Microsoft Defender for Endpoint (+ Defender AV)
  - SentinelOne

Recommendations are filtered to what was actually detected.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from core.models import Session

# ── Recommendation structure ───────────────────────────────────────────────────
# Each rec: title, description, priority, steps (list of strings)
# priority: critical | high | medium | low

_FALCON: dict[str, list[dict]] = {
    "__general__": [
        {
            "title": "Set Prevention Policy to Aggressive",
            "description": "Ensure the sensor Prevention Policy is in 'Prevent' mode (not 'Detect Only') for script-based execution, process hollowing, and credential theft.",
            "priority": "critical",
            "steps": [
                "Navigate to Falcon Console → Configuration → Prevention Policies.",
                "Select the applicable policy for Windows endpoints.",
                "Enable 'Suspicious Script Execution' under Script Control → set to Prevent.",
                "Enable 'Interpreter Only' and 'PowerShell Script Logging' collection.",
                "Deploy updated policy to all sensor groups.",
            ],
        },
        {
            "title": "Enable Real-Time Response (RTR)",
            "description": "RTR allows immediate remote investigation and containment when a detection fires.",
            "priority": "high",
            "steps": [
                "Falcon Console → Configuration → Response Policies → enable RTR.",
                "Ensure analysts have RTR Analyst role at minimum.",
                "Configure auto-containment triggers for P1_INCIDENT tier alerts.",
            ],
        },
        {
            "title": "Configure Fusion SOAR Workflow for High-Severity Alerts",
            "description": "Automate triage actions (notify, isolate, collect) on Critical detections.",
            "priority": "high",
            "steps": [
                "Falcon Console → Fusion → Create new workflow.",
                "Trigger: Detection Severity = Critical.",
                "Actions: Send Slack/Teams notification → contain host → create ticket.",
            ],
        },
        {
            "title": "Enable Custom IOA Rule Groups",
            "description": "Custom Indicators of Attack let you write behavioral rules beyond the built-in detections.",
            "priority": "medium",
            "steps": [
                "Falcon Console → Configuration → Custom IOA Rule Groups → Create Group.",
                "Write process-level rules targeting PowerShell parent-child chains.",
                "Test in 'Monitor Only' before switching to 'Prevent'.",
            ],
        },
    ],
    "AMSI_BYPASS_REFLECT": [
        {
            "title": "Custom IOA: Detect AMSI Patching via Reflection",
            "description": "Write a Custom IOA that triggers when powershell.exe command line or loaded assembly references amsiInitFailed or AmsiScanBuffer.",
            "priority": "critical",
            "steps": [
                "Falcon → Configuration → Custom IOA Rule Groups → New Rule.",
                "Platform: Windows | Rule Type: Process Creation.",
                "ImageFileName: contains 'powershell'.",
                "CommandLine: contains 'amsiInitFailed' OR 'AmsiScanBuffer'.",
                "Set Action: Alert + Prevent Process.",
            ],
        },
    ],
    "AMSI_BYPASS_COM": [
        {
            "title": "Custom IOA: AMSI COM Object Bypass",
            "description": "Detect COM-based AMSI bypass by monitoring for IAmsiStream or AmsiInitialize in PowerShell script blocks.",
            "priority": "critical",
            "steps": [
                "Create Custom IOA → Process Creation rule for powershell.exe.",
                "CommandLine: contains 'IAmsiStream' OR 'AmsiInitialize' OR 'amsi.AMSI'.",
                "Action: Prevent + Alert.",
            ],
        },
    ],
    "DOWNLOAD_CRADLE_WC": [
        {
            "title": "Block PowerShell Outbound HTTP via Network Prevention",
            "description": "Prevent PowerShell processes from making direct HTTP/S download calls using Falcon's network policy.",
            "priority": "high",
            "steps": [
                "Falcon → Configuration → Prevention Policies → Network Protection.",
                "Enable 'Block Suspicious Network Traffic from Processes'.",
                "Add powershell.exe to monitored process list.",
                "Custom IOA: Image=powershell.exe + NetworkConnect to untrusted domains → Prevent.",
            ],
        },
    ],
    "REFLECTIVE_INJECT": [
        {
            "title": "Enable Reflective DLL Injection Prevention",
            "description": "Falcon's behavioral engine detects reflective loading. Ensure this is in Prevent, not Detect.",
            "priority": "critical",
            "steps": [
                "Prevention Policy → Process Injection → set 'Reflective DLL Injection' to Prevent.",
                "Enable 'Memory Scanning' for process injection artifacts.",
                "Custom IOA: Target process=powershell + ImageLoad containing VirtualAlloc + WriteProcessMemory sequence.",
            ],
        },
    ],
    "SHELLCODE_MARSHAL": [
        {
            "title": "Enable Memory Injection Shellcode Detection",
            "description": "Prevent shellcode staging via .NET Marshal by enabling memory scanning and P/Invoke monitoring.",
            "priority": "critical",
            "steps": [
                "Prevention Policy → Malware → enable 'Suspicious Process' prevention.",
                "Enable 'Memory Scanning' in sensor settings.",
                "Custom IOA: PowerShell + DotNet loaded + AllocHGlobal call chain.",
            ],
        },
    ],
    "CRED_HARVEST": [
        {
            "title": "Enable Credential Theft Prevention",
            "description": "Falcon can prevent LSASS dumping and Mimikatz-style credential access at the process level.",
            "priority": "critical",
            "steps": [
                "Prevention Policy → Identity Protection → enable 'Credential Theft Prevention'.",
                "Enable 'LSASS Read' blocking.",
                "Custom IOA: Process accessing lsass.exe memory → Prevent + Alert.",
                "Enable Falcon Identity Protection if licensed.",
            ],
        },
    ],
    "WMI_PERSIST": [
        {
            "title": "Enable WMI Activity Monitoring",
            "description": "Detect and prevent WMI permanent event subscription creation via PowerShell.",
            "priority": "high",
            "steps": [
                "Prevention Policy → Persistence → enable 'WMI Activity Monitoring'.",
                "Custom IOA: Process=powershell.exe creating __EventFilter or ActiveScriptEventConsumer.",
                "Alert SOC on any WMI persistence attempt from non-admin accounts.",
            ],
        },
    ],
    "COBALT_STRIKE": [
        {
            "title": "Enable Cobalt Strike Beacon Detection",
            "description": "Falcon has built-in Cobalt Strike beacon signatures. Ensure they are in Prevent mode.",
            "priority": "critical",
            "steps": [
                "Prevention Policy → Malware → 'Known Malware' → set to Prevent.",
                "Enable 'Suspicious Processes' behavioral category → Prevent.",
                "Custom IOA for GzipStream+FromBase64String+IEX combination.",
                "Review Falcon Threat Graph for any lateral movement from the affected host.",
            ],
        },
    ],
    "REVERSE_SHELL": [
        {
            "title": "Block Interactive Reverse Shell Connections",
            "description": "Prevent PowerShell from creating interactive TCP sessions to external hosts.",
            "priority": "critical",
            "steps": [
                "Custom IOA: powershell.exe → NetworkConnect to non-corporate IP → Prevent.",
                "Enable 'Custom Network Containment' rule for PowerShell outbound on non-standard ports.",
                "Consider containing the host immediately if this fires in production.",
            ],
        },
    ],
    "ETW_BYPASS": [
        {
            "title": "Detect ETW Patching Attempts",
            "description": "ETW bypass is a stealth technique. Falcon can detect writes to ntdll.dll function memory.",
            "priority": "high",
            "steps": [
                "Custom IOA: powershell.exe + write to EtwEventWrite function region.",
                "Enable 'Suspicious PowerShell Commands' behavioral detection.",
                "Alert: Any script block referencing 'EtwEventWrite' or 'PatchEtw'.",
            ],
        },
    ],
    "AV_EXCLUSION": [
        {
            "title": "Alert on AV Policy Modification Attempts",
            "description": "Attacker disabling Defender while Falcon is present is a defense evasion signal.",
            "priority": "high",
            "steps": [
                "Custom IOA: powershell.exe CommandLine contains 'Add-MpPreference' or 'Set-MpPreference'.",
                "Action: Alert + optional containment.",
                "Verify whether Falcon policy requires Defender to be active as a complement.",
            ],
        },
    ],
    "ENCODED_CMD": [
        {
            "title": "Custom IOA: Encoded Command Flag",
            "description": "Flag and optionally prevent PowerShell invocations using -EncodedCommand.",
            "priority": "medium",
            "steps": [
                "Custom IOA: Process=powershell.exe + CommandLine matches -E(nc|C) + base64 string.",
                "Start in 'Alert' mode to baseline legitimate uses (e.g., CI/CD).",
                "Escalate to 'Prevent' after baselining.",
            ],
        },
    ],
}


_DEFENDER: dict[str, list[dict]] = {
    "__general__": [
        {
            "title": "Enable All Attack Surface Reduction Rules in Block Mode",
            "description": "Microsoft's ASR rules cover the most common PowerShell and Office-based attack vectors. Audit mode first, then block.",
            "priority": "critical",
            "steps": [
                "Intune → Endpoint Security → Attack Surface Reduction → Create Policy.",
                "Start with all rules in 'Audit' mode for 2 weeks to identify FPs.",
                "Switch critical rules to 'Block': Script obfuscation (5BEB7EFE), LSASS access (9E6C4E1F), WMI persistence (E6DB77E5).",
                "Monitor ASR events in MDE Advanced Hunting: `DeviceEvents | where ActionType startswith 'AsrPowerShell'`.",
            ],
        },
        {
            "title": "Enable Network Protection in Block Mode",
            "description": "Blocks PowerShell and other processes from connecting to known malicious IPs/domains.",
            "priority": "high",
            "steps": [
                "Intune → Device Configuration → Defender ATP → Network Protection → Block.",
                "Or via PowerShell: Set-MpPreference -EnableNetworkProtection Enabled.",
                "Verify coverage in MDE Security Center → Device configuration.",
            ],
        },
        {
            "title": "Enable Cloud-Delivered Protection at High Level",
            "description": "Zero-day and emerging threat detection relies on cloud telemetry. Set to 'High' or 'High Plus'.",
            "priority": "high",
            "steps": [
                "Intune → Endpoint Security → Antivirus → Cloud-delivered protection level: High.",
                "Enable 'Automatic sample submission' for unknown files.",
                "Verify MAPS connection: Test-NetConnection -ComputerName wdcp.microsoft.com -Port 443.",
            ],
        },
        {
            "title": "Deploy PowerShell Constrained Language Mode via WDAC",
            "description": "WDAC (Windows Defender Application Control) can force PowerShell into Constrained Language Mode, blocking most post-exploitation techniques.",
            "priority": "high",
            "steps": [
                "Create a WDAC policy in audit mode using WDAC Wizard tool.",
                "Test for 30 days; review AppLocker/WDAC event log for blocked scripts.",
                "Deploy enforcement policy via Intune → Windows → Custom OMA-URI.",
            ],
        },
        {
            "title": "Enable MDE Custom Detection Rules",
            "description": "Use Advanced Hunting KQL queries as scheduled custom detections that fire alerts automatically.",
            "priority": "medium",
            "steps": [
                "MDE Portal → Hunting → Custom Detection Rules → Create Rule.",
                "Set frequency to every 1 hour for critical rules, 24 hours for informational.",
                "Map each rule to a MITRE ATT&CK technique for automatic categorization.",
            ],
        },
    ],
    "AMSI_BYPASS_REFLECT": [
        {
            "title": "ASR Rule: Block Obfuscated Script Execution",
            "description": "Enable ASR rule 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC to block potentially obfuscated scripts.",
            "priority": "critical",
            "steps": [
                "Intune → ASR Policy → 'Block execution of potentially obfuscated scripts' → Block.",
                "MDE Custom Detection: `DeviceEvents | where ActionType == 'PowerShellCommand' | where AdditionalFields has_any ('amsiInitFailed','AmsiScanBuffer')`.",
                "Ensure AMSI integration is active: `Get-MpComputerStatus | Select-Object AMSIEnabled`.",
            ],
        },
    ],
    "AMSI_BYPASS_COM": [
        {
            "title": "ASR Rule: Block COM Object Instantiation",
            "description": "Use ASR rule to restrict COM object creation from script interpreters.",
            "priority": "critical",
            "steps": [
                "Enable ASR rule: 'Block COM object creation from Office macros' (applies to script hosts too).",
                "Custom Detection: `DeviceEvents | where AdditionalFields has_any ('IAmsiStream','AmsiInitialize')`.",
            ],
        },
    ],
    "DOWNLOAD_CRADLE_WC": [
        {
            "title": "ASR: Block JS/VBScript Download Execution + Network Protection",
            "description": "Block scripts from launching downloaded content and prevent direct HTTP download cradles.",
            "priority": "high",
            "steps": [
                "ASR: 'Block JavaScript or VBScript from launching downloaded executable content' → Block.",
                "Network Protection → Block mode (covers WebClient download to malicious URLs).",
                "Custom Detection: `DeviceEvents | where ActionType == 'PowerShellCommand' | where AdditionalFields has 'Net.WebClient' and AdditionalFields has 'DownloadString'`.",
            ],
        },
    ],
    "REFLECTIVE_INJECT": [
        {
            "title": "ASR: Block Process Injection + Enable Memory Integrity",
            "description": "Prevent reflective injection via ASR and Virtualization-Based Security.",
            "priority": "critical",
            "steps": [
                "Enable Credential Guard + Memory Integrity (HVCI) via Intune.",
                "ASR rule: 'Block process creation from PSExec and WMI commands' → Block.",
                "Custom Detection: `DeviceEvents | where ActionType == 'CreateRemoteThreadApiCall'`.",
            ],
        },
    ],
    "CRED_HARVEST": [
        {
            "title": "ASR: Block LSASS Credential Theft + Enable Credential Guard",
            "description": "Two-layer protection: ASR rule 9E6C4E1F blocks LSASS access; Credential Guard isolates credentials in a VM.",
            "priority": "critical",
            "steps": [
                "ASR: 'Block credential stealing from the Windows local security authority subsystem' (9E6C4E1F) → Block.",
                "Enable Windows Defender Credential Guard via Intune → Device Config → Identity Protection.",
                "Custom Detection: `DeviceEvents | where ActionType == 'LsassAccessGranted'`.",
            ],
        },
    ],
    "WMI_PERSIST": [
        {
            "title": "ASR: Block WMI Event Subscription Persistence",
            "description": "ASR rule E6DB77E5 specifically targets WMI-based persistence.",
            "priority": "high",
            "steps": [
                "ASR: 'Block persistence through WMI event subscription' (E6DB77E5) → Block.",
                "Custom Detection: `DeviceEvents | where ActionType == 'WmiBindEventFilter'`.",
            ],
        },
    ],
    "COBALT_STRIKE": [
        {
            "title": "Enable Behavioral Monitoring + Cobalt Strike Signatures",
            "description": "MDE's behavioral engine detects CS stager patterns. Ensure real-time protection is in full prevention mode.",
            "priority": "critical",
            "steps": [
                "Defender AV: Set-MpPreference -BehaviorMonitoringEnabled 1.",
                "Enable 'Block at first sight' for unknown executables.",
                "Custom Detection: `DeviceProcessEvents | where ProcessCommandLine has 'GzipStream' and ProcessCommandLine has 'FromBase64String'`.",
                "Isolate affected device immediately via MDE portal if detected.",
            ],
        },
    ],
    "REVERSE_SHELL": [
        {
            "title": "Network Protection + Custom Detection for Reverse Shell",
            "description": "Block PowerShell outbound TCP sessions to non-corporate IP ranges.",
            "priority": "critical",
            "steps": [
                "Network Protection → Block mode.",
                "Custom Detection: `DeviceNetworkEvents | where InitiatingProcessFileName == 'powershell.exe' | where RemotePort !in (80, 443)` — alert on uncommon outbound ports.",
                "Custom Detection: `DeviceNetworkEvents | where InitiatingProcessFileName == 'powershell.exe' | where RemoteIPType == 'Public'`.",
            ],
        },
    ],
    "ETW_BYPASS": [
        {
            "title": "Detect ETW Patching via Behavioral Telemetry",
            "description": "MDE behavioral sensors can detect writes to ntdll.dll regions used by ETW.",
            "priority": "high",
            "steps": [
                "Ensure MDE sensor telemetry is enabled at 'Full' level in device configuration.",
                "Custom Detection: `DeviceEvents | where ActionType == 'PowerShellCommand' | where AdditionalFields has 'EtwEventWrite'`.",
                "Alert + auto-investigation trigger on this detection.",
            ],
        },
    ],
    "AV_EXCLUSION": [
        {
            "title": "Alert on Defender Policy Modification via MDE",
            "description": "Any attempt to add AV exclusions or disable real-time protection is an immediate indicator.",
            "priority": "high",
            "steps": [
                "Custom Detection: `DeviceEvents | where ActionType == 'AntivirusExclusionAdded'`.",
                "Custom Detection: `DeviceProcessEvents | where ProcessCommandLine has 'Set-MpPreference' and ProcessCommandLine has 'DisableRealtimeMonitoring'`.",
                "Consider blocking Set-MpPreference for non-SYSTEM accounts via AppLocker.",
            ],
        },
    ],
    "ENCODED_CMD": [
        {
            "title": "Flag Encoded Command Usage via Custom Detection",
            "description": "Legitimate use of -EncodedCommand should be rare. Flag and review.",
            "priority": "medium",
            "steps": [
                "Custom Detection: `DeviceProcessEvents | where ProcessCommandLine matches regex @'-E(nc(odedCommand)?|C)\\s+[A-Za-z0-9+/]{30,}'`.",
                "Allowlist known CI/CD service accounts via exclusion in the detection rule.",
                "Alert on any interactive user session running encoded commands.",
            ],
        },
    ],
}


_SENTINELONE: dict[str, list[dict]] = {
    "__general__": [
        {
            "title": "Set All Policies to Protect Mode",
            "description": "SentinelOne has three modes: Detect, Protect, and Protect+. Endpoints should be in Protect to actively block threats.",
            "priority": "critical",
            "steps": [
                "SentinelOne Console → Sentinels → Policies → select policy group.",
                "Threat Detection: Static AI + Dynamic (Behavioral) AI → both set to Protect.",
                "Anti-Tampering: Enable to prevent agent removal by attackers.",
                "Review and resolve any conflicts before switching production groups.",
            ],
        },
        {
            "title": "Enable Deep Visibility Telemetry",
            "description": "Deep Visibility provides full EDR telemetry (process, network, file, registry). Required for threat hunting and STAR rules.",
            "priority": "high",
            "steps": [
                "Policy → Deep Visibility → set to Full.",
                "Ensure sufficient storage quota in management console.",
                "Test a hunt query: Storyline search for EventType = 'Process Creation' on a test endpoint.",
            ],
        },
        {
            "title": "Configure STAR (Custom Detection) Rules",
            "description": "STAR rules allow writing PowerShell Query Language (S1QL) behavioral detections that fire real-time alerts.",
            "priority": "high",
            "steps": [
                "Console → Visibility → STAR Rules → Create New Rule.",
                "Write S1QL query for the detected technique.",
                "Set Action: Alert + optionally Kill Process or Quarantine.",
                "Set Time Frame and test against historical data first.",
            ],
        },
        {
            "title": "Enable Network Quarantine Policy for Critical Alerts",
            "description": "Automatically isolate a machine from the network when a P1-level threat is detected.",
            "priority": "high",
            "steps": [
                "Policy → Response Actions → Network Quarantine → enable auto-quarantine on Critical threats.",
                "Define quarantine exceptions: allow VPN/management IP ranges.",
                "Test quarantine and release workflow with your IR team.",
            ],
        },
        {
            "title": "Integrate Threat Intelligence Feeds",
            "description": "SentinelOne supports TI integrations (MISP, TAXII, custom IOC uploads) for proactive IOC-based blocking.",
            "priority": "medium",
            "steps": [
                "Console → Settings → Integrations → Threat Intelligence.",
                "Connect MISP or upload IOCs extracted from this analysis (URLs, IPs, hashes).",
                "Set IOC match action to Block + Alert.",
            ],
        },
    ],
    "AMSI_BYPASS_REFLECT": [
        {
            "title": "STAR Rule: Detect AMSI Bypass via Reflection",
            "description": "Write a behavioral STAR rule that fires when powershell.exe loads scripts containing AMSI patching strings.",
            "priority": "critical",
            "steps": [
                "STAR Rule query: `EventType = 'Script' AND SrcProcess.Name = 'powershell.exe' AND ScriptContent Contains 'amsiInitFailed'`.",
                "Action: Kill Process + Alert.",
                "Enable 'Suspicious PowerShell Activity' behavioral category in Prevention Policy.",
            ],
        },
    ],
    "AMSI_BYPASS_COM": [
        {
            "title": "STAR Rule: AMSI COM Bypass",
            "description": "Detect COM-based AMSI bypass in script block content.",
            "priority": "critical",
            "steps": [
                "STAR Rule: `EventType = 'Script' AND SrcProcess.Name = 'powershell.exe' AND (ScriptContent Contains 'IAmsiStream' OR ScriptContent Contains 'AmsiInitialize')`.",
                "Action: Kill Process + Alert.",
            ],
        },
    ],
    "DOWNLOAD_CRADLE_WC": [
        {
            "title": "Script Control + STAR Rule for Download Cradles",
            "description": "SentinelOne Script Control can block unsigned or untrusted scripts. Combine with a STAR rule for WebClient detection.",
            "priority": "high",
            "steps": [
                "Policy → Application Control → Script Control → enable for PowerShell.",
                "STAR Rule: `EventType = 'Network' AND SrcProcess.Name = 'powershell.exe' AND NetworkDirection = 'OUTGOING'`.",
                "Alert on any PowerShell outbound network connection to non-approved IPs.",
            ],
        },
    ],
    "REFLECTIVE_INJECT": [
        {
            "title": "Enable Memory Scanning + Behavioral AI for Injection",
            "description": "SentinelOne's Dynamic AI detects reflective injection patterns at runtime.",
            "priority": "critical",
            "steps": [
                "Policy → Detection → Dynamic (Behavioral) AI → Protect mode.",
                "Enable 'In-Memory Threat Detection' (scans process memory for injected code).",
                "STAR Rule: `EventType = 'Injection' AND TgtProcess.Name != SrcProcess.Name`.",
            ],
        },
    ],
    "SHELLCODE_MARSHAL": [
        {
            "title": "In-Memory Shellcode Detection",
            "description": "Enable deep memory scanning to catch shellcode allocated via .NET Marshal.",
            "priority": "critical",
            "steps": [
                "Policy → Dynamic AI → set 'Suspicious In-Memory Artifacts' to Protect.",
                "STAR Rule: `EventType = 'Script' AND SrcProcess.Name = 'powershell.exe' AND ScriptContent Contains 'AllocHGlobal' AND ScriptContent Contains 'GetDelegateForFunctionPointer'`.",
                "Action: Kill Process + Quarantine.",
            ],
        },
    ],
    "CRED_HARVEST": [
        {
            "title": "Enable Credential Theft Protection + LSASS Monitoring",
            "description": "Prevent Mimikatz-style dumping by protecting LSASS process access.",
            "priority": "critical",
            "steps": [
                "Policy → Protection → Credential Theft → Protect mode.",
                "STAR Rule: `EventType = 'Process Access' AND TgtProcess.Name = 'lsass.exe' AND SrcProcess.Name = 'powershell.exe'`.",
                "Action: Kill Source Process + Alert.",
            ],
        },
    ],
    "WMI_PERSIST": [
        {
            "title": "STAR Rule: WMI Event Subscription",
            "description": "Detect WMI permanent event subscription creation via PowerShell.",
            "priority": "high",
            "steps": [
                "STAR Rule: `EventType = 'WMI Create' AND SrcProcess.Name = 'powershell.exe' AND ObjectType Contains 'EventFilter'`.",
                "Alert: High severity → trigger IR workflow.",
                "Policy → Behavioral AI covers WMI persistence natively; verify it is in Protect.",
            ],
        },
    ],
    "COBALT_STRIKE": [
        {
            "title": "Cobalt Strike Detection via Static + Behavioral AI",
            "description": "CS beacons are well-known to S1 Static AI. Ensure both engines are active.",
            "priority": "critical",
            "steps": [
                "Policy → Static AI → set to Protect (catches CS beacon PE artifacts).",
                "Policy → Dynamic AI → set to Protect (catches CS staging behavior).",
                "STAR Rule: `EventType = 'Script' AND ScriptContent Contains 'GzipStream' AND ScriptContent Contains 'FromBase64String'`.",
                "Enable Auto-Quarantine for Critical threats.",
                "Review all active network connections from the affected host in Deep Visibility.",
            ],
        },
    ],
    "REVERSE_SHELL": [
        {
            "title": "Network Quarantine + STAR Rule for Reverse Shells",
            "description": "Detect and automatically isolate hosts establishing reverse shell connections.",
            "priority": "critical",
            "steps": [
                "STAR Rule: `EventType = 'Network' AND SrcProcess.Name = 'powershell.exe' AND DstPort NotIn [80, 443, 8080, 8443]`.",
                "Action: Kill Process + Network Quarantine.",
                "Review Deep Visibility Network events for destination IP reputation via Threat Intelligence.",
            ],
        },
    ],
    "ETW_BYPASS": [
        {
            "title": "STAR Rule: ETW Patching Attempt",
            "description": "Detect scripts referencing ETW function names as an indicator of evasion intent.",
            "priority": "high",
            "steps": [
                "STAR Rule: `EventType = 'Script' AND SrcProcess.Name = 'powershell.exe' AND (ScriptContent Contains 'EtwEventWrite' OR ScriptContent Contains 'PatchEtw')`.",
                "Action: Kill Process + Alert.",
            ],
        },
    ],
    "AV_EXCLUSION": [
        {
            "title": "STAR Rule: AV Policy Tampering",
            "description": "Detect attempts to add Defender exclusions or disable AV features.",
            "priority": "high",
            "steps": [
                "STAR Rule: `EventType = 'Script' AND ScriptContent Contains 'Add-MpPreference' AND ScriptContent Contains 'ExclusionPath'`.",
                "Also alert on: `ScriptContent Contains 'DisableRealtimeMonitoring'`.",
                "Action: Kill Process + Alert — this should be treated as a confirmed incident.",
            ],
        },
    ],
    "ENCODED_CMD": [
        {
            "title": "STAR Rule: Encoded PowerShell Execution",
            "description": "Flag encoded command usage and alert for analyst review.",
            "priority": "medium",
            "steps": [
                "STAR Rule: `EventType = 'Process Creation' AND ProcessName = 'powershell.exe' AND CmdLine Contains '-EncodedCommand'`.",
                "Set action to Alert first; monitor for 2 weeks before blocking.",
                "Allowlist known service accounts (e.g., SCCM, backup agents).",
            ],
        },
    ],
}


_CORTEX: dict[str, list[dict]] = {
    "__general__": [
        {
            "title": "Set Prevention Mode to Enabled",
            "description": "Cortex XDR agents operate in three modes: Disabled, Detect, and Enabled (Prevent). All production endpoints must be in Enabled mode.",
            "priority": "critical",
            "steps": [
                "Cortex XDR Console → Endpoints → Policy Management → select policy.",
                "Protection Mode → set to 'Enabled' for all module categories.",
                "Anti-Tampering → enable to prevent agent removal or policy bypass.",
                "Push updated policy to all endpoint groups and verify acceptance.",
            ],
        },
        {
            "title": "Enable Behavioral Threat Protection (BTP)",
            "description": "BTP is Cortex XDR's AI-driven behavioral engine that detects attack chains even when individual events appear benign.",
            "priority": "critical",
            "steps": [
                "Policy → Malware Security Profile → Behavioral Threat Protection → Enabled.",
                "Set child process protection to 'Enabled' under Process Execution.",
                "Enable 'Script-based Attack Protection' for PowerShell, WScript, CScript.",
            ],
        },
        {
            "title": "Configure Action Center for Automated Response",
            "description": "Action Center lets you define automatic remediation responses (isolate, kill, quarantine) triggered by alert severity.",
            "priority": "high",
            "steps": [
                "Console → Response → Action Center → configure response templates.",
                "High Severity alert → auto-isolate endpoint from network.",
                "Critical alert → kill malicious process + quarantine file + isolate.",
                "Notify SOC via webhook/email on any Critical alert.",
            ],
        },
        {
            "title": "Enable XQL Threat Hunting",
            "description": "XQL (XDR Query Language) lets you hunt across Cortex XDR telemetry for the exact patterns found in this analysis.",
            "priority": "high",
            "steps": [
                "Console → Investigation → XQL Query Center → open query editor.",
                "Use dataset = xdr_data for process and network events.",
                "Schedule automated XQL hunt queries to run daily against critical IOCs.",
                "Save confirmed hunt queries as Custom Correlation Rules for continuous detection.",
            ],
        },
        {
            "title": "Enable Exploit Prevention Modules",
            "description": "Cortex XDR's exploit prevention modules block memory corruption, shellcode injection, and code execution techniques.",
            "priority": "high",
            "steps": [
                "Exploit Security Profile → enable all prevention modules.",
                "Key modules: Heap Spray, Stack Pivot, ROP, Shellcode, DLL Security.",
                "Set each module to 'Block and Terminate' (not just report).",
                "Test against a known PoC in a lab environment before production rollout.",
            ],
        },
    ],
    "AMSI_BYPASS_REFLECT": [
        {
            "title": "XQL Hunt + Custom Correlation: AMSI Patching",
            "description": "Write an XQL query to detect AMSI bypass patterns, then promote it to a Custom Correlation Rule.",
            "priority": "critical",
            "steps": [
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter actor_process_image_name ~= '(?i)powershell.exe' | filter action_process_image_command_line ~= '(?i)amsiInitFailed|AmsiScanBuffer'`.",
                "Promote to Custom Correlation Rule: Console → Correlations → Create Rule.",
                "Trigger Action: Isolate + Kill Process.",
            ],
        },
    ],
    "AMSI_BYPASS_COM": [
        {
            "title": "Custom Correlation: AMSI COM Bypass",
            "description": "Detect COM-based AMSI bypass in PowerShell command lines.",
            "priority": "critical",
            "steps": [
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter actor_process_image_name ~= '(?i)powershell.exe' | filter action_process_image_command_line ~= '(?i)IAmsiStream|AmsiInitialize'`.",
                "Promote to Correlation Rule with HIGH severity.",
                "Action: Alert + Kill Process.",
            ],
        },
    ],
    "DOWNLOAD_CRADLE_WC": [
        {
            "title": "Network Protection + XQL Hunt for Download Cradles",
            "description": "Block PowerShell outbound connections to untrusted endpoints and detect WebClient download patterns.",
            "priority": "high",
            "steps": [
                "Policy → Network Protection → enable 'Restrict Suspicious Traffic from Script Interpreters'.",
                "XQL: `dataset = xdr_data | filter event_type = ENUM.NETWORK | filter actor_process_image_name ~= '(?i)powershell.exe' | filter dst_action_external_hostname != null`.",
                "Correlate network events with process events containing 'Net.WebClient' and 'DownloadString'.",
            ],
        },
    ],
    "REFLECTIVE_INJECT": [
        {
            "title": "Enable DLL Security + Injection Prevention",
            "description": "Cortex XDR Exploit Prevention can block reflective DLL injection and PE loading from memory.",
            "priority": "critical",
            "steps": [
                "Exploit Security Profile → DLL Security → enable 'Block Unknown DLL Loads'.",
                "Enable 'Prevent Injection' under Exploit Prevention.",
                "XQL: `dataset = xdr_data | filter event_type = ENUM.INJECTION | filter actor_process_image_name ~= '(?i)powershell.exe'`.",
                "Action on match: Block + Kill Injected Process.",
            ],
        },
    ],
    "SHELLCODE_MARSHAL": [
        {
            "title": "Enable Shellcode Protection Module",
            "description": "Cortex XDR has a dedicated shellcode prevention module that detects .NET Marshal-based shellcode staging.",
            "priority": "critical",
            "steps": [
                "Exploit Security Profile → Shellcode Prevention → set to 'Block and Terminate'.",
                "Enable 'Stack Pivot' and 'Heap Spray' protection modules.",
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter actor_process_image_command_line ~= '(?i)AllocHGlobal' and actor_process_image_command_line ~= '(?i)GetDelegateForFunctionPointer'`.",
            ],
        },
    ],
    "CRED_HARVEST": [
        {
            "title": "Enable Credential Gathering Protection",
            "description": "Cortex XDR blocks LSASS access patterns and credential dumping tools.",
            "priority": "critical",
            "steps": [
                "Policy → Malware Protection → Credential Gathering → set to 'Enabled'.",
                "Enable 'Protected Process' for lsass.exe.",
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter action_process_image_name ~= '(?i)lsass.exe' | filter actor_process_image_name ~= '(?i)powershell.exe'`.",
                "Action: Immediately isolate the endpoint on match.",
            ],
        },
    ],
    "WMI_PERSIST": [
        {
            "title": "WMI Behavioral Detection via Correlation",
            "description": "Detect WMI event subscription creation from PowerShell as a persistence mechanism.",
            "priority": "high",
            "steps": [
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter actor_process_image_name ~= '(?i)wmic.exe|powershell.exe' | filter action_process_image_command_line ~= '__EventFilter|ActiveScriptEventConsumer'`.",
                "Promote to Custom Correlation Rule.",
                "Action: Alert + block WMI process.",
            ],
        },
    ],
    "COBALT_STRIKE": [
        {
            "title": "Known C2 Signatures + Behavioral Correlation",
            "description": "Cortex XDR cloud threat intelligence includes Cobalt Strike beacon signatures. Ensure cloud lookup is active.",
            "priority": "critical",
            "steps": [
                "Policy → WildFire Integration → enable cloud lookups for all executable types.",
                "XQL: `dataset = xdr_data | filter event_type = ENUM.NETWORK | filter actor_process_image_name ~= '(?i)powershell.exe' | filter dst_port in (80, 443, 8080, 8443) | filter dst_action_external_hostname != null`.",
                "Threat Intel: upload C2 IPs/domains extracted from this analysis as IOC block list.",
                "Enable auto-isolation on Cobalt Strike beacon detection.",
            ],
        },
    ],
    "REVERSE_SHELL": [
        {
            "title": "Block PowerShell Reverse Connections via Network Policy",
            "description": "Prevent interactive PowerShell reverse shell sessions by blocking outbound TCP from the interpreter.",
            "priority": "critical",
            "steps": [
                "Policy → Network Protection → restrict powershell.exe outbound to known-good destinations.",
                "XQL: `dataset = xdr_data | filter event_type = ENUM.NETWORK | filter actor_process_image_name ~= '(?i)powershell.exe' | filter dst_port not in (80, 443) | filter action_network_connection_status = ESTABLISHED`.",
                "Action Center: auto-isolate + kill process on reverse shell detection.",
            ],
        },
    ],
    "ETW_BYPASS": [
        {
            "title": "Custom Correlation: ETW Evasion",
            "description": "Detect attempts to patch ETW functions, which indicates an attacker trying to evade logging.",
            "priority": "high",
            "steps": [
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter actor_process_image_command_line ~= '(?i)EtwEventWrite|PatchEtw'`.",
                "Promote to Correlation Rule — severity HIGH.",
                "Action: Kill Process + Alert SOC — ETW patching means the attacker is actively trying to hide.",
            ],
        },
    ],
    "AV_EXCLUSION": [
        {
            "title": "Alert on AV Policy Tampering via Correlation",
            "description": "Any script attempting to disable or add exclusions to security tools is a high-fidelity indicator.",
            "priority": "high",
            "steps": [
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter actor_process_image_command_line ~= '(?i)Add-MpPreference|DisableRealtimeMonitoring|DisableAntiSpyware'`.",
                "Promote to Correlation Rule — severity HIGH.",
                "Action: Alert + optionally kill process. Review why Defender was targeted while Cortex XDR is present.",
            ],
        },
    ],
    "ENCODED_CMD": [
        {
            "title": "Custom Correlation: Encoded PowerShell",
            "description": "Flag -EncodedCommand usage for analyst review; baseline before blocking.",
            "priority": "medium",
            "steps": [
                "XQL: `dataset = xdr_data | filter event_type = ENUM.PROCESS | filter actor_process_image_name ~= '(?i)powershell.exe' | filter action_process_image_command_line ~= '-E(nc|C) '`.",
                "Start as Alert only. Run for 2 weeks to identify legitimate CI/CD or admin use.",
                "Allowlist specific service accounts, then promote to Block mode.",
            ],
        },
    ],
}


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class Recommendation:
    title:       str
    description: str
    priority:    str
    steps:       list[str]
    triggered_by: str = ""  # technique_id that triggered this, or "" for general


@dataclass
class EDRHardening:
    slug:            str   # falcon | defender | s1
    name:            str
    color:           str
    general:         list[Recommendation]
    triggered:       list[Recommendation]


# ── Public generator ───────────────────────────────────────────────────────────

def generate_hardening(sessions: list[Session]) -> list[EDRHardening]:
    """Return hardening recs for all four EDRs, filtered to detected techniques."""
    detected = _detected_techniques(sessions)
    return [
        _build_edr("falcon",   "CrowdStrike Falcon",             "#E8002D", _FALCON,      detected),
        _build_edr("defender", "Microsoft Defender for Endpoint", "#0078D4", _DEFENDER,   detected),
        _build_edr("s1",       "SentinelOne",                    "#6600FF", _SENTINELONE, detected),
        _build_edr("cortex",   "Palo Alto Cortex XDR",           "#FA582D", _CORTEX,      detected),
    ]


def _detected_techniques(sessions: list[Session]) -> set[str]:
    seen: set[str] = set()
    for s in sessions:
        if s.weighted_score < 40:
            continue
        for block in s.blocks:
            for finding in block.findings:
                seen.add(finding.technique_id)
    return seen


def _build_edr(
    slug: str,
    name: str,
    color: str,
    data: dict[str, list[dict]],
    detected: set[str],
) -> EDRHardening:
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    general = [
        Recommendation(**{k: v for k, v in r.items()}, triggered_by="")
        for r in data.get("__general__", [])
    ]

    triggered: list[Recommendation] = []
    for tech_id in detected:
        for r in data.get(tech_id, []):
            triggered.append(Recommendation(**{k: v for k, v in r.items()}, triggered_by=tech_id))

    triggered.sort(key=lambda r: priority_order.get(r.priority, 4))
    return EDRHardening(slug=slug, name=name, color=color, general=general, triggered=triggered)
