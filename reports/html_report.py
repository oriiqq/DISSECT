"""
ps_classifier — HTML report generator

Produces analyst-ready investigation reports from Session and Campaign objects.
"""

from __future__ import annotations
import html
from datetime import datetime
from pathlib import Path

from core.models import Session, Campaign, TempoClass


# ── Colour helpers ────────────────────────────────────────────────────────────

def _tier_colour(tier: str) -> tuple[str, str]:
    """(background, text) hex pair for alert tier badges."""
    return {
        "P1_INCIDENT": ("#FCEBEB", "#791F1F"),
        "P2_ALERT":    ("#FAEEDA", "#633806"),
        "P3_WARNING":  ("#E1F5EE", "#085041"),
        "INFO":        ("#E6F1FB", "#0C447C"),
        "CLEAN":       ("#F1EFE8", "#2C2C2A"),
    }.get(tier, ("#F1EFE8", "#2C2C2A"))


def _sev_colour(sev: int) -> tuple[str, str]:
    if sev >= 80: return ("#FCEBEB", "#791F1F")
    if sev >= 60: return ("#FAEEDA", "#633806")
    if sev >= 40: return ("#E1F5EE", "#085041")
    return ("#E6F1FB", "#0C447C")


def _tempo_label(tempo: TempoClass) -> str:
    return {
        TempoClass.INTERACTIVE_OPERATOR: "Interactive operator",
        TempoClass.AUTOMATED_STAGER:     "Automated stager",
        TempoClass.LATERAL_SWEEP:        "Lateral sweep",
        TempoClass.MIXED:                "Mixed",
        TempoClass.SINGLE_BLOCK:         "Single block",
    }.get(tempo, str(tempo))


# ── Session narrative ─────────────────────────────────────────────────────────

def _build_narrative(session: Session) -> str:
    """Generate a plain-English attack narrative from a session."""
    lines = []
    ts    = session.start_time.strftime("%H:%M:%S UTC") if session.start_time else "unknown time"
    host  = html.escape(session.host_id)

    lines.append(f"At <strong>{ts}</strong> on <code>{host}</code> (PID {session.process_id}), "
                 f"a {_tempo_label(session.tempo).lower()} executed {len(session.blocks)} "
                 f"script block{'s' if len(session.blocks) != 1 else ''}.")

    tech_display = {
        "AMSI_BYPASS_REFLECT": "bypassed AMSI via .NET reflection",
        "AMSI_BYPASS_COM":     "bypassed AMSI via COM object",
        "DOWNLOAD_CRADLE_WC":  "downloaded a remote payload using Net.WebClient",
        "DOWNLOAD_CRADLE_BITS":"transferred files via BITS",
        "REFLECTIVE_INJECT":   "performed reflective PE injection",
        "SHELLCODE_MARSHAL":   "executed shellcode via Runtime.Marshal",
        "CRED_HARVEST":        "attempted credential harvesting (Mimikatz-style)",
        "COBALT_STRIKE":       "deployed what appears to be a Cobalt Strike stager",
        "REVERSE_SHELL":       "established a reverse shell over TCP",
        "WMI_PERSIST":         "installed WMI event subscription persistence",
        "REG_PERSIST":         "added a registry Run key for persistence",
        "ETW_BYPASS":          "patched ETW to disable event logging",
        "AV_EXCLUSION":        "added a Defender exclusion",
    }

    found_techs = []
    for tech in session.technique_set:
        if tech in tech_display:
            found_techs.append(tech_display[tech])
    if found_techs:
        lines.append("The session " + ", then ".join(found_techs) + ".")

    if session.iocs:
        ioc_sample = [html.escape(i) for i in session.iocs[:5]]
        lines.append(f"Extracted IOCs: <code>{'</code>, <code>'.join(ioc_sample)}</code>"
                     + (" (and more)" if len(session.iocs) > 5 else "") + ".")

    if session.campaign_id:
        lines.append(f"This session is part of campaign <code>{html.escape(session.campaign_id)}</code>, "
                     f"indicating the same operator was active on other hosts.")

    return " ".join(lines)


# ── Main report builder ───────────────────────────────────────────────────────

def generate_report(sessions: list[Session],
                    campaigns: list[Campaign] | None = None,
                    title: str = "PS Classifier — Investigation Report") -> str:
    """
    Render a standalone HTML report for the given sessions and campaigns.
    Returns the full HTML string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    alerted = [s for s in sessions if s.alert_tier not in ("CLEAN", "INFO")]
    p1 = sum(1 for s in sessions if s.alert_tier == "P1_INCIDENT")
    p2 = sum(1 for s in sessions if s.alert_tier == "P2_ALERT")
    p3 = sum(1 for s in sessions if s.alert_tier == "P3_WARNING")

    # ── Session rows ──────────────────────────────────────────────────────────
    session_rows = ""
    for s in sorted(sessions, key=lambda x: -x.weighted_score):
        bg, fg = _tier_colour(s.alert_tier)
        narrative = _build_narrative(s) if s.weighted_score >= 40 else ""
        techniques_html = " ".join(
            f'<span style="font-size:11px;padding:2px 6px;border-radius:4px;'
            f'background:#EEEDFE;color:#3C3489">{html.escape(t)}</span>'
            for t in sorted(s.technique_set)
        )
        ioc_html = ""
        if s.iocs:
            iocs = [html.escape(i) for i in s.iocs[:8]]
            ioc_html = f'<div style="margin-top:6px;font-size:11px;color:#5F5E5A">IOCs: {", ".join(iocs)}</div>'

        narrative_html = f'<div style="margin-top:8px;font-size:12.5px;color:#3d3d3a;line-height:1.6">{narrative}</div>' if narrative else ""

        session_rows += f"""
        <tr>
          <td style="padding:10px 12px;vertical-align:top;border-bottom:0.5px solid #e8e6e0">
            <span style="font-size:10px;font-weight:500;padding:2px 8px;border-radius:8px;
                         background:{bg};color:{fg}">{s.alert_tier}</span>
          </td>
          <td style="padding:10px 12px;vertical-align:top;border-bottom:0.5px solid #e8e6e0;font-family:monospace;font-size:12px">
            {html.escape(s.host_id)}
          </td>
          <td style="padding:10px 12px;vertical-align:top;border-bottom:0.5px solid #e8e6e0;font-size:13px;font-weight:500">
            {round(s.weighted_score)}
          </td>
          <td style="padding:10px 12px;vertical-align:top;border-bottom:0.5px solid #e8e6e0;font-size:12px">
            {html.escape(_tempo_label(s.tempo))}
          </td>
          <td style="padding:10px 12px;vertical-align:top;border-bottom:0.5px solid #e8e6e0">
            {techniques_html}
            {ioc_html}
            {narrative_html}
          </td>
        </tr>"""

    # ── Campaign rows ──────────────────────────────────────────────────────────
    campaign_section = ""
    if campaigns:
        campaign_rows = ""
        for c in campaigns:
            status = "Confirmed" if c.is_confirmed else "Tentative"
            bg = "#FCEBEB" if c.is_confirmed else "#FAEEDA"
            fg = "#791F1F" if c.is_confirmed else "#633806"
            first = c.first_seen.strftime("%Y-%m-%d %H:%M") if c.first_seen else "—"
            last  = c.last_seen.strftime("%Y-%m-%d %H:%M") if c.last_seen else "—"
            hosts = ", ".join(html.escape(h) for h in sorted(c.host_ids))
            campaign_rows += f"""
            <tr>
              <td style="padding:8px 12px;border-bottom:0.5px solid #e8e6e0;font-family:monospace;font-size:12px">{html.escape(c.campaign_id)}</td>
              <td style="padding:8px 12px;border-bottom:0.5px solid #e8e6e0">
                <span style="font-size:10px;font-weight:500;padding:2px 8px;border-radius:8px;background:{bg};color:{fg}">{status}</span>
              </td>
              <td style="padding:8px 12px;border-bottom:0.5px solid #e8e6e0;font-size:12px">{len(c.sessions)}</td>
              <td style="padding:8px 12px;border-bottom:0.5px solid #e8e6e0;font-size:12px">{len(c.host_ids)}</td>
              <td style="padding:8px 12px;border-bottom:0.5px solid #e8e6e0;font-size:12px">{c.peak_severity}</td>
              <td style="padding:8px 12px;border-bottom:0.5px solid #e8e6e0;font-family:monospace;font-size:11px">{hosts}</td>
              <td style="padding:8px 12px;border-bottom:0.5px solid #e8e6e0;font-size:11px">{first} → {last}</td>
            </tr>"""

        campaign_section = f"""
        <h2 style="font-size:16px;font-weight:500;margin:2rem 0 0.75rem">Cross-host campaigns</h2>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="border-bottom:1px solid #d3d1c7">
              <th style="text-align:left;padding:6px 12px;font-size:11px;color:#5F5E5A;text-transform:uppercase;letter-spacing:.04em">Campaign ID</th>
              <th style="text-align:left;padding:6px 12px;font-size:11px;color:#5F5E5A;text-transform:uppercase;letter-spacing:.04em">Status</th>
              <th style="text-align:left;padding:6px 12px;font-size:11px;color:#5F5E5A;text-transform:uppercase;letter-spacing:.04em">Sessions</th>
              <th style="text-align:left;padding:6px 12px;font-size:11px;color:#5F5E5A;text-transform:uppercase;letter-spacing:.04em">Hosts</th>
              <th style="text-align:left;padding:6px 12px;font-size:11px;color:#5F5E5A;text-transform:uppercase;letter-spacing:.04em">Peak Sev</th>
              <th style="text-align:left;padding:6px 12px;font-size:11px;color:#5F5E5A;text-transform:uppercase;letter-spacing:.04em">Hosts</th>
              <th style="text-align:left;padding:6px 12px;font-size:11px;color:#5F5E5A;text-transform:uppercase;letter-spacing:.04em">Timespan</th>
            </tr>
          </thead>
          <tbody>{campaign_rows}</tbody>
        </table>"""

    # ── Full HTML ──────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
          background: #fafaf8; color: #1a1a18; font-size: 14px; line-height: 1.6; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }}
  h1 {{ font-size: 20px; font-weight: 500; margin-bottom: 4px; }}
  .meta {{ font-size: 12px; color: #5F5E5A; margin-bottom: 1.5rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 10px; margin-bottom: 1.75rem; }}
  .stat {{ background: #f1efe8; border-radius: 8px; padding: 12px 16px; }}
  .stat .label {{ font-size: 11px; color: #5F5E5A; text-transform: uppercase;
                  letter-spacing: .04em; margin-bottom: 4px; }}
  .stat .value {{ font-size: 24px; font-weight: 500; }}
  h2 {{ font-size: 16px; font-weight: 500; margin: 1.75rem 0 0.75rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead tr {{ border-bottom: 1px solid #d3d1c7; }}
  th {{ text-align: left; padding: 6px 12px; font-size: 11px; color: #5F5E5A;
        text-transform: uppercase; letter-spacing: .04em; }}
  code {{ font-family: "SF Mono", "Fira Code", monospace; font-size: 0.9em;
          background: #f1efe8; padding: 1px 5px; border-radius: 3px; }}
  .footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 0.5px solid #d3d1c7;
             font-size: 11px; color: #888780; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>{html.escape(title)}</h1>
  <div class="meta">Generated {now} &nbsp;·&nbsp; {len(sessions)} sessions analysed</div>

  <div class="stats">
    <div class="stat"><div class="label">P1 Incidents</div>
      <div class="value" style="color:#A32D2D">{p1}</div></div>
    <div class="stat"><div class="label">P2 Alerts</div>
      <div class="value" style="color:#854F0B">{p2}</div></div>
    <div class="stat"><div class="label">P3 Warnings</div>
      <div class="value" style="color:#0F6E56">{p3}</div></div>
    <div class="stat"><div class="label">Total sessions</div>
      <div class="value">{len(sessions)}</div></div>
    <div class="stat"><div class="label">Campaigns</div>
      <div class="value">{len(campaigns) if campaigns else 0}</div></div>
  </div>

  <h2>Sessions</h2>
  <table>
    <thead>
      <tr>
        <th>Tier</th><th>Host</th><th>Score</th><th>Tempo</th><th>Findings</th>
      </tr>
    </thead>
    <tbody>{session_rows}</tbody>
  </table>

  {campaign_section}

  <div class="footer">
    ps_classifier &nbsp;·&nbsp; report generated {now}
  </div>
</div>
</body>
</html>"""


def save_report(sessions: list[Session],
                output_path: str | Path,
                campaigns: list[Campaign] | None = None,
                title: str = "PS Classifier — Investigation Report") -> Path:
    """Generate and write the HTML report. Returns the output path."""
    html_content = generate_report(sessions, campaigns=campaigns, title=title)
    path = Path(output_path)
    path.write_text(html_content, encoding="utf-8")
    return path
