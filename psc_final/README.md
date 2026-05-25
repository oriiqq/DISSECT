# ps_classifier

**PowerShell transcript anomaly classifier for DFIR teams.**

Ingests Windows Event ID 4104 (Script Block Logging) from `.evtx` files or SIEM
JSON exports, runs a full detection pipeline, and produces ranked session alerts,
cross-host campaign clusters, auto-generated Sigma rules, and analyst-ready HTML
investigation reports — all from a single command or a browser UI.

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [How it is different from existing tools](#2-how-it-is-different)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [Quick start — 60 seconds to first result](#5-quick-start)
6. [Enabling PowerShell Script Block Logging](#6-enabling-script-block-logging)
7. [Getting your log files](#7-getting-your-log-files)
8. [CLI walkthrough](#8-cli-walkthrough)
9. [Web UI walkthrough](#9-web-ui-walkthrough)
10. [Understanding the output](#10-understanding-the-output)
11. [Building an environment baseline](#11-building-an-environment-baseline)
12. [Extending the rule library](#12-extending-the-rule-library)
13. [Project layout](#13-project-layout)
14. [Architecture and pipeline](#14-architecture-and-pipeline)
15. [Running the tests](#15-running-the-tests)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. What it does

ps_classifier takes raw PowerShell log data and:

- **Deobfuscates** script blocks before analysis — backtick removal, Base64 decoding,
  char-code substitution, format-string resolution, hex arrays, reversed strings, and
  more, applied in iterative passes until stable.
- **Classifies** each block against 21 built-in detection rules covering AMSI bypass,
  download cradles, reflective injection, shellcode via Marshal, Cobalt Strike stagers,
  reverse shells, WMI persistence, credential harvesting, ETW bypass, Defender exclusions,
  and high-entropy blob detection.
- **Stitches sessions** by grouping blocks from the same host and process ID within a
  configurable time window, so you see the full attack chain rather than isolated events.
- **Scores sessions** on a 0–100 scale with TTP chain bonuses (AMSI bypass + download
  cradle together scores higher than either alone) and attacker tempo bonuses.
- **Classifies tempo** — interactive human operator, automated stager, or mixed — from
  inter-block timing statistics.
- **Correlates campaigns** across hosts by fingerprinting each operator's obfuscation
  style. The same operator hitting 10 hosts produces one confirmed campaign, not 10
  separate incidents.
- **Generates Sigma rules** for every detected technique, ready to deploy into any
  Sigma-compatible SIEM backend.
- **Produces an HTML investigation report** with plain-English attack narratives,
  technique summaries, extracted IOCs, and a full session timeline.

---

## 2. How it is different

| Capability | ps_classifier | Chainsaw | DeepBlueCLI | Revoke-Obfuscation | SigmaHQ |
|---|:---:|:---:|:---:|:---:|:---:|
| Cross-platform (no PS runtime needed) | ✓ | ✓ | ✗ | ✗ | ✓ |
| Multi-layer deobfuscation | ✓ | ✗ | ✗ | ✓ | ✗ |
| Session stitching (PID + time gap) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Cross-host campaign correlation | ✓ | ✗ | ✗ | ✗ | ✗ |
| Attacker tempo classification | ✓ | ✗ | ✗ | ✗ | ✗ |
| Per-environment baseline (FP suppression) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Auto-generated Sigma rules | ✓ | ✗ | ✗ | ✗ | N/A |
| Web UI with htmx | ✓ | ✗ | ✗ | ✗ | ✗ |
| Human-readable HTML report | ✓ | ✗ | ✗ | ✗ | ✗ |
| EVTX + JSON input | ✓ | ✓ | ✓ | ✗ | ✓ |

**The key unique capability** is cross-host fingerprinting: an attacker's obfuscation
style (chunk sizes, char-code offset values, IEX nesting depth, backtick density) stays
stable even when payloads change. ps_classifier hashes this style fingerprint and clusters
sessions from different hosts into campaigns. A lateral movement sweep that looks like 30
separate low-severity alerts in other tools shows up here as one confirmed campaign.

---

## 3. Requirements

- Python 3.11 or newer
- For EVTX file parsing: `python-evtx` and `lxml`
- For the web UI: `fastapi`, `uvicorn`, `jinja2`, `python-multipart`

All listed in `requirements.txt`.

---

## 4. Installation

```bash
# Clone or download and extract the project
cd ps_classifier/

# Install all dependencies
pip install -r requirements.txt

# Verify the install
python psc.py --help
```

If you only want CLI without the web UI:
```bash
pip install pyyaml python-evtx lxml
```

If you only want JSON input (no EVTX parsing):
```bash
pip install pyyaml fastapi uvicorn jinja2 python-multipart
```

### `requirements.txt`

```
pyyaml>=6.0
python-evtx>=0.7.4
lxml>=4.9
fastapi>=0.110
uvicorn>=0.29
jinja2>=3.1
python-multipart>=0.0.9
httpx>=0.27          # needed for test suite only
pytest>=8.0          # needed for test suite only
```

---

## 5. Quick start

A test log file (`test_logs.json`) is included. It contains 14 realistic events
across 5 hosts: 3 attacker sessions and 2 clean sessions.

**Option A — CLI, one command:**
```bash
python psc.py analyse --input test_logs.json --report report.html
```
Open `report.html` in your browser. You should see 2–3 P1/P2 sessions,
extracted IOCs (192.168.45.100, 10.10.10.50), and technique badges.

**Option B — Web UI:**
```bash
python psc.py serve
# or
uvicorn web.app:app --port 8000
```
Open `http://localhost:8000`, click **Upload EVTX / JSON**, select `test_logs.json`.
The dashboard populates instantly. Click any session row to see the detail panel
with script blocks, deobfuscated text, and auto-generated Sigma rules.

---

## 6. Enabling Script Block Logging

PowerShell Script Block Logging (Event ID 4104) is **off by default**. You must
enable it on target machines before any logs exist to analyse.

### Via Group Policy (recommended for AD environments)

```
Computer Configuration →
  Administrative Templates →
    Windows Components →
      Windows PowerShell →
        Turn on PowerShell Script Block Logging → Enabled
```

Also enable **Turn on Module Logging** and **Turn on Script Execution** in the same
location for complete coverage.

### Via registry (single machine or remote)

```powershell
# Run as Administrator on the target machine
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1

# Optional: also log script block invocation start
Set-ItemProperty -Path $path -Name "EnableScriptBlockInvocationLogging" -Value 1
```

### Remote via PowerShell remoting

```powershell
Invoke-Command -ComputerName VICTIM-PC-01, VICTIM-PC-02 -ScriptBlock {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1
}
```

After enabling, logs appear at:
```
Applications and Services Logs →
  Microsoft →
    Windows →
      PowerShell →
        Operational
```

The log file on disk is at:
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
```

> **Note:** The Security log (`Security.evtx`) does NOT contain 4104 events.
> You want the PowerShell Operational log, not the Security log.

---

## 7. Getting your log files

### From a live machine (copy the EVTX directly)

```powershell
# Copy off a live machine — run from your analysis workstation
Copy-Item "\\VICTIM-PC-01\C$\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" .\victim01_ps.evtx
```

### From Event Viewer (GUI export)

1. Open Event Viewer on the target machine
2. Navigate to `Applications and Services Logs → Microsoft → Windows → PowerShell → Operational`
3. Right-click → **Save All Events As** → choose `.evtx` format
4. Transfer the file to your analysis machine

### From a SIEM — Splunk

```spl
index=wineventlog EventCode=4104 earliest=-7d
| table _time, host, ProcessId, ThreadId, ScriptBlockId, ScriptBlockText, MessageNumber, MessageTotal, Path
| outputlookup ps_logs.csv
```

Then convert to JSON:
```bash
python -c "
import csv, json, sys
with open('ps_logs.csv') as f:
    rows = list(csv.DictReader(f))
# Rename Splunk field names to what the tool expects
for r in rows:
    r['TimeCreated'] = r.pop('_time', '')
    r['Computer'] = r.pop('host', 'unknown')
print(json.dumps(rows, indent=2))
" > ps_logs.json
```

Or use Splunk's built-in JSON export: add `| outputlookup ps_logs.json` or use the
search UI's Export → JSON option.

### From a SIEM — Elastic / OpenSearch

```json
GET winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.event_id": 4104}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ]
    }
  },
  "_source": ["@timestamp", "winlog.computer_name", "winlog.process.pid",
               "winlog.process.thread.id", "winlog.event_data.ScriptBlockText",
               "winlog.event_data.ScriptBlockId", "winlog.event_data.MessageNumber",
               "winlog.event_data.MessageTotal", "winlog.event_data.Path"],
  "size": 10000
}
```

Export the response and save as `ps_logs.json`. The tool handles nested `_source` format
from Elastic automatically.

### From Velociraptor (hunt)

```vql
SELECT System.TimeCreated.SystemTime AS TimeCreated,
       System.Computer AS Computer,
       System.Execution.ProcessID AS ProcessId,
       EventData.ScriptBlockText AS ScriptBlockText,
       EventData.ScriptBlockId AS ScriptBlockId,
       EventData.MessageNumber AS MessageNumber,
       EventData.MessageTotal AS MessageTotal,
       EventData.Path AS Path
FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx")
WHERE System.EventID.Value = 4104
```

Export as JSON from the Velociraptor UI.

### JSON format accepted

The tool accepts any of these formats automatically:

**Flat array (simplest):**
```json
[
  {
    "ScriptBlockText": "amsiInitFailed",
    "Computer": "VICTIM-PC",
    "ProcessId": 1234,
    "TimeCreated": "2024-06-01T14:22:00Z",
    "ScriptBlockId": "some-guid",
    "MessageNumber": 1,
    "MessageTotal": 1
  }
]
```

**Splunk results wrapper:**
```json
{ "results": [ { "_time": "...", "host": "...", "ScriptBlockText": "..." } ] }
```

**Elastic hits wrapper:**
```json
{ "hits": { "hits": [ { "_source": { "@timestamp": "...", "Computer": "...", "ScriptBlockText": "..." } } ] } }
```

The only required field is `ScriptBlockText`. Everything else has sensible defaults
(host defaults to `"unknown"`, timestamps default to now, PIDs default to 0).

---

## 8. CLI walkthrough

### `analyse` — run the full detection pipeline

```bash
python psc.py analyse --input <file> [options]
```

**Basic analysis, print summary to stdout:**
```bash
python psc.py analyse --input victim_ps.evtx
```

**Full analysis with all outputs:**
```bash
python psc.py analyse \
  --input victim_ps.evtx \
  --report report.html \
  --sigma-out sigma_rules/ \
  --json-out results.json
```

**With baseline (reduces false positives from legitimate automation):**
```bash
# Step 1: build a baseline from known-good logs first (see section 11)
python psc.py baseline --input clean_logs.json --save baseline.json

# Step 2: analyse with the baseline
python psc.py analyse \
  --input victim_ps.evtx \
  --baseline baseline.json \
  --report report.html
```

**Tune session gap (default 120 seconds):**
```bash
# If attackers are slow (long dwell time), increase the gap
python psc.py analyse --input logs.evtx --session-gap 300

# If you want tight sessions (fast automated stagers), decrease it
python psc.py analyse --input logs.evtx --session-gap 30
```

**All CLI options:**
```
--input        Required. Path to .evtx or .json log file
--report       Write standalone HTML investigation report to this path
--sigma-out    Directory to write Sigma rule .yml files (one per technique)
--json-out     Write structured JSON results to this path
--baseline     Path to baseline.json for false-positive suppression
--session-gap  Session boundary time gap in seconds (default: 120)
```

**Example output:**
```
──────────────────────────────────────────────────
  ps_classifier results
──────────────────────────────────────────────────
  Sessions total : 8
  P1 Incidents   : 2
  P2 Alerts      : 1
  P3 Warnings    : 1
  Campaigns      : 1
──────────────────────────────────────────────────

  Top sessions:
    [P1_INCIDENT  ] VICTIM-PC-01                   score=100 tempo=interactive_operator techs=AMSI_BYPASS_REFLECT,COBALT_STRIKE,DOWNLOAD_CRADLE_WC,REVERSE_SHELL
    [P1_INCIDENT  ] VICTIM-PC-02                   score=97  tempo=mixed               techs=AV_EXCLUSION,CRED_HARVEST,SCHTASK_CREATE,WMI_PERSIST
```

### `baseline` — build an environment baseline

```bash
python psc.py baseline --input <known-good-logs> --save baseline.json
```

See [Section 11](#11-building-an-environment-baseline) for full details.

### `serve` — start the web dashboard

```bash
python psc.py serve
```

Options:
```
--host    Bind host (default: 127.0.0.1)
--port    Port (default: 8000)
--reload  Enable auto-reload for development
```

Examples:
```bash
# Default (localhost only, safe)
python psc.py serve

# Listen on all interfaces (for server deployment)
python psc.py serve --host 0.0.0.0 --port 8741

# Development mode with auto-reload
python psc.py serve --reload
```

---

## 9. Web UI walkthrough

Start the server:
```bash
python psc.py serve
```
Open `http://localhost:8000` in your browser.

### Step 1 — Upload your log file

Click **Upload EVTX / JSON** in the top bar. The file picker accepts `.evtx`,
`.json`, `.jsonl`, and `.ndjson`. Select your file. The analysis runs automatically
on upload (no separate submit button).

For large EVTX files (50–200 MB) expect 5–30 seconds processing time. The spinner
in the button indicates it's working.

### Step 2 — Read the stats strip

Five cards appear at the top:
- **P1 Incidents** — sessions scoring ≥ 80. Immediate triage required.
- **P2 Alerts** — sessions scoring 60–79. Review within the hour.
- **P3 Warnings** — sessions scoring 40–59. Review end of day.
- **Sessions** — total sessions found (including clean ones).
- **Campaigns** — clusters of sessions sharing an obfuscation fingerprint across
  2+ hosts.

### Step 3 — Session table

Sessions are sorted by score descending. Each row shows:
- **Tier badge** — P1/P2/P3/INFO/CLEAN with colour coding
- **Score** — 0–100 weighted severity
- **Host** — hostname from the log
- **PID** — process ID (useful for correlating with Sysmon Event 1)
- **Blocks** — number of script blocks in this session
- **Tempo** — interactive operator / automated stager / mixed
- **Techniques** — technique ID badges for every finding in the session
- **IOCs** — count of extracted URLs, IPs, and hashes
- **Time** — session start timestamp

### Step 4 — Session detail panel

Click any session row. A detail panel expands below the table showing:

**Metadata bar** — host, PID, score, block count, tempo, campaign ID (if
the session is part of a cross-host cluster).

**Techniques detected** — all technique IDs found across blocks in the session.

**Extracted IOCs** — all URLs, IPs, file paths, and hashes extracted from
decoded script text.

**Auto-generated Sigma rules** — one card per technique. Each card shows the
rule title, severity level, MITRE ID, and tags. Click **View YAML** to expand
the full Sigma rule text ready to copy and deploy.

**Script blocks** — every script block in the session, showing:
- Severity score (colour-coded)
- Timestamp and Shannon entropy
- Source file path (if logged)
- Technique badges for that specific block
- Decoded text (after all deobfuscation passes)
- A collapsible **Raw** section showing the original text before deobfuscation,
  so you can see what the deobfuscator unwrapped

### Step 5 — Campaign section

If any sessions share an obfuscation fingerprint across 2+ hosts, a Campaigns
section appears below the session table. Each campaign card shows:
- **Confirmed** (2+ hosts, 3+ sessions) or **Tentative** (fewer)
- Campaign ID (a short hash of the obfuscation fingerprint)
- Session count and host count
- Peak severity across all sessions
- All involved hostnames
- First and last seen timestamps

A confirmed campaign means the same operator — identified by their obfuscation
style, not just IOCs — hit multiple machines.

### Step 6 — Downloads

Three download links are available:
- **Download Sigma rules** (sidebar or link below stats strip) — all rules from
  the current analysis as a single combined YAML file, deduplicated across sessions.
  Each technique appears once regardless of how many sessions triggered it.
- **Download HTML report** — a standalone HTML file you can email, attach to a
  ticket, or archive. Contains the full session table, campaign section, and
  plain-English attack narratives.
- **Clear** button (top right, only shown when data is loaded) — resets the
  analysis so you can load a different file.

---

## 10. Understanding the output

### Alert tiers

| Tier | Score range | Meaning |
|---|---|---|
| P1_INCIDENT | 80–100 | Active or recent attack chain. Immediate triage. |
| P2_ALERT | 60–79 | Significant suspicious activity. Review within 1 hour. |
| P3_WARNING | 40–59 | Suspicious but ambiguous. Review end of day. |
| INFO | 1–39 | Low-severity signals. Periodic batch review. |
| CLEAN | 0 | No findings. Confirmed baseline or below threshold. |

### Scoring explained

**Block severity (0–100):**
- Base score = highest finding severity in the block
- Combination bonus = +8 per additional distinct technique (max +15)
- Entropy bonus = +10 if block entropy > 5.5 and a rule fired

**Session score (0–100):**
- Weighted average: 40% max block score + 60% (70% weight on top-3 blocks + 30%
  average of all blocks)
- Chain bonuses applied on top:
  - AMSI bypass + download cradle together: +15
  - Double AMSI bypass (reflect + COM): +8
  - Reflective injection or shellcode via Marshal: +20
  - Cobalt Strike indicators: +20
  - Reverse shell + download cradle: +15
- Tempo bonus: interactive operator (human at keyboard): +10

### Technique IDs

| Technique ID | Description | MITRE |
|---|---|---|
| AMSI_BYPASS_REFLECT | amsiInitFailed / AmsiScanBuffer via reflection | T1562.001 |
| AMSI_BYPASS_COM | COM object AMSI bypass | T1562.001 |
| DOWNLOAD_CRADLE_WC | Net.WebClient download | T1105 |
| DOWNLOAD_CRADLE_BITS | BITS transfer download | T1197 |
| DOWNLOAD_CRADLE_IWR | Invoke-WebRequest download | T1105 |
| REFLECTIVE_INJECT | Invoke-ReflectivePEInjection | T1055.001 |
| SHELLCODE_MARSHAL | AllocHGlobal + GetDelegateForFunctionPointer | T1055 |
| CLM_BYPASS | Constrained Language Mode bypass | T1059.001 |
| CRED_HARVEST | Mimikatz / sekurlsa / lsadump | T1003.001 |
| WMI_PERSIST | WMI event subscription | T1546.003 |
| SCHTASK_CREATE | Scheduled task creation | T1053.005 |
| ENCODED_CMD | -EncodedCommand flag | T1059.001 |
| ETW_BYPASS | EtwEventWrite patching | T1562.006 |
| AV_EXCLUSION | Defender exclusion / disable | T1562.001 |
| REG_PERSIST | Registry Run key | T1547.001 |
| REVERSE_SHELL | TcpClient reverse shell | T1059.001 |
| IEX_EXEC | Invoke-Expression (loader indicator) | T1059.001 |
| EXEC_POLICY_BYPASS | -ExecutionPolicy Bypass | T1059.001 |
| PROC_HOLLOW | Process hollowing | T1055.012 |
| COM_LATERAL | COM lateral movement | T1021.003 |
| COBALT_STRIKE | Cobalt Strike stager patterns | T1059.001 |
| HIGH_ENTROPY_BLOB | High-entropy block (heuristic) | T1059.001 |

### Attacker tempo

| Tempo | Meaning |
|---|---|
| interactive_operator | Human at keyboard. Blocks arrive 2–300s apart with high variance. Most dangerous — adapts in real time. |
| automated_stager | Script executing. Blocks arrive <0.5s apart with low variance. Predictable, possibly less adaptive. |
| lateral_sweep | Identical blocks across 3+ hosts in a short window. Automated lateral movement. |
| mixed | Transition between phases — may indicate automation handing off to interactive. |
| single_block | Only one block in the session — insufficient timing data. |

### Sigma output

Generated rules use `experimental` status and target the
`ps_script_block_logging` log category. Every rule includes:
- Unique UUID in the `id` field
- MITRE ATT&CK reference URL
- Session context in the description (host, timestamp, matched text)
- Specific detection conditions — not generic signatures

Rules are ready to validate with `sigma check` and convert with `sigmac` or
`pySigma` for your SIEM backend:
```bash
# Convert to Splunk SPL
sigma convert -t splunk ps_classifier_sigma.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch ps_classifier_sigma.yml

# Convert to KQL (Microsoft Sentinel)
sigma convert -t sentinel ps_classifier_sigma.yml
```

---

## 11. Building an environment baseline

Every environment has legitimate PowerShell automation — Azure Automation,
DSC agents, CI/CD pipelines, monitoring scripts. Without a baseline, these
generate false positives. With a baseline, they are suppressed.

### Collect known-good logs first

Run normal operations for 7–14 days with Script Block Logging enabled. Export
the logs before any known compromise period. These are your "clean" logs.

```bash
# Build baseline from known-good EVTX
python psc.py baseline \
  --input clean_logs.evtx \
  --save baseline.json

# Or from JSON export
python psc.py baseline \
  --input clean_export.json \
  --save baseline.json
```

Output:
```
  Baseline saved: baseline.json
  Observations:  4821
  Unique cmdlets: 312
```

### Extend an existing baseline

Each time you run a new clean period, extend rather than replace:
```bash
python psc.py baseline \
  --input new_clean_week.json \
  --save baseline.json   # loads existing, extends, saves back
```

### Use baseline during analysis

```bash
python psc.py analyse \
  --input suspicious.evtx \
  --baseline baseline.json \
  --report report.html
```

### How suppression works

The baseline stores:
- **Cmdlet frequency** — how often each cmdlet appears in your environment
- **Known script hashes** — SHA-256 of every clean block's decoded content
- **Known paths** — trusted script file paths

At analysis time, each block gets an anomaly score:
- Exact content hash match → anomaly score 0.0 (fully suppressed)
- Trusted path → anomaly score multiplied by 0.3
- Cmdlets seen < 5 times total → high rarity penalty
- Cmdlets never seen before → highest rarity penalty
- High entropy compared to environment mean → entropy bonus

The anomaly score is stored in `session.baseline_anomaly` and is available
in the JSON output. The baseline needs at least 100 observations before it
activates — before that threshold it does nothing rather than incorrectly
suppress novel tooling.

---

## 12. Extending the rule library

Rules are loaded from `patterns/rules.yaml` at startup. If the file does not
exist, the 21 built-in rules are used. To add custom rules, create the file:

```yaml
# patterns/rules.yaml
rules:
  - name: my_custom_rule
    technique_id: MY_TECH_ID
    mitre_id: T1059.001
    severity: 80
    description: "What this detects and why it matters"
    tags:
      - custom
      - execution
    patterns:
      - 'SuspiciousCmdlet\s*\('
      - 'another\.pattern\.here'
```

Rules are regex patterns applied to `decoded_text` (after deobfuscation) with
`re.IGNORECASE | re.MULTILINE`. Any matching pattern fires the rule. All fields
are required except `description` and `tags`.

Severity guidelines:
- 90–100 = Critical. Direct code execution or full compromise capability.
- 75–89 = High. Strong indicator, few false positives.
- 50–74 = Medium. Suspicious but context-dependent.
- 25–49 = Low. Informational, high false positive rate.

---

## 13. Project layout

```
ps_classifier/
│
├── psc.py                         ← CLI entry point
│                                     Commands: analyse, baseline, serve
│
├── core/
│   ├── models.py                  ← All data structures
│   │                                 ScriptBlock, Session, Campaign,
│   │                                 Finding, ObfuscationFingerprint, RuleMetrics
│   │
│   ├── deobfuscator.py            ← Multi-layer deobfuscation engine
│   │                                 8 transforms, up to 12 iterative passes
│   │
│   ├── classifier.py              ← Rule engine
│   │                                 Loads rules.yaml or built-ins
│   │                                 Applies patterns to decoded_text
│   │
│   ├── ingest.py                  ← Ingest, stitch, score
│   │                                 parse_evtx(), parse_json_export()
│   │                                 reassemble_multipart()
│   │                                 stitch_sessions(), enrich_session()
│   │                                 score_block(), score_session()
│   │
│   ├── fingerprinter.py           ← Cross-host campaign correlation
│   │                                 extract_fingerprint()
│   │                                 cluster_into_campaigns()
│   │
│   └── baseline.py                ← Per-environment baseline
│                                     EnvironmentBaseline.ingest_benign()
│                                     EnvironmentBaseline.anomaly_score()
│
├── reports/
│   ├── sigma.py                   ← Sigma rule generator
│   │                                 generate_sigma_rules(session)
│   │                                 generate_sigma_for_sessions(sessions)
│   │
│   └── html_report.py             ← HTML investigation report
│                                     generate_report(sessions, campaigns)
│
├── web/
│   ├── app.py                     ← FastAPI application
│   │                                 Routes: /, /upload, /sessions/{id},
│   │                                 /sigma/download, /report/download,
│   │                                 /state (DELETE), /api/stats
│   │
│   ├── static/                    ← (empty — all CSS is inline)
│   │
│   └── templates/
│       ├── index.html             ← Shell layout, sidebar, topbar
│       └── partials/
│           ├── dashboard.html     ← Stats strip, session table, campaigns
│           └── session_detail.html← Detail panel, Sigma rules, script blocks
│
├── patterns/
│   └── rules.yaml                 ← Custom rules (optional, auto-created on first use)
│
├── tests/
│   ├── test_core.py               ← 34 tests: models, deobfuscator, classifier,
│   │                                 ingest, stitcher, scorer, baseline, campaigns
│   └── test_sigma_web.py          ← 26 tests: sigma generator, FastAPI endpoints,
│                                     upload pipeline, state management
│
├── test_logs.json                 ← Sample logs for testing (14 events, 5 hosts)
└── requirements.txt
```

---

## 14. Architecture and pipeline

Every analysis run follows these stages in order:

```
Input file (.evtx or .json)
        │
        ▼
┌─────────────────────┐
│  1. Ingest          │  parse_evtx() or parse_json_export()
│                     │  → iterator of raw ScriptBlock objects
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  2. Deobfuscate     │  deobfuscate() called during ingest
│                     │  → decoded_text field populated on each block
│                     │  8 transforms, up to 12 passes until stable
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  3. Reassemble      │  reassemble_multipart()
│                     │  Join MessageNumber fragments by ScriptBlockId
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  4. Classify        │  Classifier.classify_batch()
│                     │  Apply all rules to decoded_text
│                     │  Populate block.findings list
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  5. Stitch sessions │  stitch_sessions()
│                     │  Group blocks by (host_id, process_id)
│                     │  Split on time gaps > SESSION_GAP
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  6. Enrich          │  enrich_session() for each session:
│                     │  - score_block() per block
│                     │  - score_session() with chain bonuses
│                     │  - classify_tempo()
│                     │  - extract_iocs() from all decoded text
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  7. Baseline score  │  EnvironmentBaseline.anomaly_score()
│     (if loaded)     │  Suppresses known-good blocks
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  8. Campaign        │  cluster_into_campaigns()
│    correlation      │  Fingerprint each session's obfuscation style
│                     │  Cluster matching fingerprints across hosts
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  9. Output          │  generate_report() → HTML
│                     │  generate_sigma_for_sessions() → YAML
│                     │  JSON serialisation → results.json
└─────────────────────┘
```

Each stage is a separate Python module. You can import and use them individually:

```python
from core.ingest import parse_evtx, stitch_sessions, enrich_session
from core.classifier import Classifier
from core.fingerprinter import cluster_into_campaigns
from reports.sigma import generate_sigma_for_sessions

clf = Classifier()
blocks = clf.classify_batch(list(parse_evtx(Path("logs.evtx"))))
sessions = stitch_sessions(blocks)
for s in sessions:
    enrich_session(s)
campaigns = cluster_into_campaigns(sessions)
bundle = generate_sigma_for_sessions(sessions)
print(bundle.to_combined_yaml())
```

---

## 15. Running the tests

```bash
# Run all 60 tests
python -m pytest tests/ -v

# Run only core pipeline tests (34 tests)
python -m pytest tests/test_core.py -v

# Run only Sigma + web tests (26 tests)
python -m pytest tests/test_sigma_web.py -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/ --cov=core --cov=reports --cov-report=term-missing
```

Expected output:
```
60 passed, 5 warnings in 0.5s
```

The 5 warnings are Python 3.12 deprecation notices for `datetime.utcnow()` —
harmless and will be fixed in a future version.

---

## 16. Troubleshooting

**"No Event ID 4104 records found"**

The file contains no script block events. Check that:
- PowerShell Script Block Logging is enabled on the source machine (see Section 6)
- You are using the PowerShell Operational log, NOT the Security log
- The correct file is `Microsoft-Windows-PowerShell%4Operational.evtx`

**"EVTX parsing requires python-evtx and lxml"**

Install the missing packages:
```bash
pip install python-evtx lxml
```

**"Module not found" errors when running psc.py**

Make sure you are running from the project root directory:
```bash
cd ps_classifier/    # must be in this directory
python psc.py analyse --input logs.json
```

**Web UI shows blank / no CSS**

The web UI uses inline CSS and loads htmx from unpkg.com. If you are on an
air-gapped network, download htmx and serve it locally:
```bash
# Download htmx
curl -o web/static/htmx.min.js https://unpkg.com/htmx.org@1.9.10/dist/htmx.min.js
```
Then edit `web/templates/index.html` and change the htmx script tag to:
```html
<script src="/static/htmx.min.js"></script>
```

**All sessions score 0 / CLEAN on a file that should have detections**

Check that `decoded_text` is being populated. The classifier runs on `decoded_text`,
not `raw_text`. If your JSON export already has plain-text script content (not
encoded), this should work fine. If the file has multi-part blocks (MessageTotal > 1),
make sure all parts are present in the export — incomplete multi-part blocks are
processed individually and may miss context.

**False positives from legitimate automation**

Build an environment baseline (Section 11). Run the tool in observation mode for
7–14 days on a non-compromised environment, then use the baseline file in all
subsequent analyses.

**Session gap is wrong — legitimate sessions split into many sessions**

Increase `--session-gap`. If you have an admin running an interactive PS session
with long pauses between commands (e.g. waiting for user input), the default 120
seconds will split it. Try `--session-gap 600` for interactive sessions.

**EVTX file is too large and times out**

Files up to 200 MB are supported. For larger files:
- Filter to only Event ID 4104 before exporting (most EVTX files contain many
  event types; a large Security.evtx may have only a few 4104 events)
- Export a time-bounded slice from your SIEM instead of the full EVTX
- For very high-volume environments, consider streaming the JSON export in batches

---

## Licence

MIT — use freely, contribute improvements back.

---

*Built for DFIR teams who need to move fast during an active incident.*
*Grounded in real attack patterns from SolarWinds, Scattered Spider,*
*Cobalt Strike campaigns, APT29, and documented ransomware playbooks.*
