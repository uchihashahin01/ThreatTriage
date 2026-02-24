"""PDF report generator for incident response reports.

Uses WeasyPrint (when available) or falls back to a clean HTML-to-PDF
simulation that generates a self-contained HTML report marked as PDF-ready.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threattriage.config import ROOT_DIR
from threattriage.logging import get_logger

logger = get_logger(__name__)

REPORTS_DIR = ROOT_DIR / "reports"


def _generate_pdf_html(report_data: dict[str, Any]) -> str:
    """Generate a print-optimized HTML document for PDF conversion."""
    exec_summary = report_data.get("executive_summary", {})
    mitre = report_data.get("mitre_attack", {})
    timeline = report_data.get("timeline", [])
    recommendations = report_data.get("recommendations", [])
    iocs = report_data.get("indicators_of_compromise", [])
    metadata = report_data.get("report_metadata", {})

    severity = exec_summary.get("severity", "medium")
    sev_colors = {
        "critical": "#ff0040",
        "high": "#ff6b00",
        "medium": "#ffb800",
        "low": "#00d4ff",
        "info": "#888",
    }
    sev_color = sev_colors.get(severity, "#888")

    techniques_html = ""
    for tech in mitre.get("techniques", []):
        techniques_html += f"""
        <tr>
            <td style="font-family:monospace;color:#00ff41;"><a href="{tech.get('url','#')}" style="color:#00ff41;text-decoration:none;">{tech['id']}</a></td>
            <td>{tech.get('name','')}</td>
            <td><span style="background:#1a1a2e;padding:2px 8px;border-radius:3px;font-size:0.8em;">{tech.get('tactic','')}</span></td>
            <td style="text-align:center;">{tech.get('detection_count',0)}</td>
        </tr>"""

    timeline_html = ""
    for event in timeline[:20]:
        timeline_html += f"""
        <tr>
            <td style="font-family:monospace;font-size:0.8em;white-space:nowrap;">{event.get('timestamp','')}</td>
            <td>{event.get('event','')}</td>
            <td><span style="color:{sev_colors.get(event.get('severity',''), '#888')};font-weight:700;text-transform:uppercase;font-size:0.8em;">{event.get('severity','')}</span></td>
            <td style="font-family:monospace;color:#00ff41;">{event.get('source_ip','')}</td>
        </tr>"""

    recs_html = ""
    for i, rec in enumerate(recommendations, 1):
        if isinstance(rec, dict):
            mitigation = rec.get("mitigation", str(rec))
            priority = rec.get("priority", "medium")
            addresses = ", ".join(rec.get("addresses_techniques", []))
        else:
            mitigation = str(rec)
            priority = "medium"
            addresses = ""
        recs_html += f"""
        <div style="background:#0a0a1a;border-left:3px solid {sev_colors.get(priority, '#ffb800')};padding:12px 16px;margin-bottom:8px;border-radius:4px;">
            <div style="font-weight:700;">{i}. {mitigation}</div>
            <div style="font-size:0.8em;color:#888;margin-top:4px;">Priority: {priority.upper()} {f'| Addresses: {addresses}' if addresses else ''}</div>
        </div>"""

    iocs_html = ""
    for ioc in iocs[:30]:
        iocs_html += f"""
        <tr>
            <td style="text-transform:uppercase;font-size:0.8em;">{ioc.get('type','')}</td>
            <td style="font-family:monospace;color:#00ff41;">{ioc.get('value','')}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Incident Report — {exec_summary.get('incident_title','')}</title>
<style>
  @page {{ size: A4; margin: 20mm; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', -apple-system, sans-serif;
    background: #0d1117; color: #c9d1d9; font-size: 11pt; line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border: 1px solid #30363d; border-radius: 8px;
    padding: 24px 32px; margin-bottom: 24px;
    border-left: 4px solid {sev_color};
  }}
  .header h1 {{ font-size: 1.4em; color: #e6edf3; margin-bottom: 8px; }}
  .header .meta {{ font-size: 0.85em; color: #8b949e; }}
  .severity-badge {{
    display: inline-block; padding: 3px 12px; border-radius: 4px;
    font-weight: 800; font-size: 0.85em; text-transform: uppercase;
    background: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color}44;
  }}
  .section {{ margin-bottom: 24px; }}
  .section h2 {{
    font-size: 1em; color: #00ff41; text-transform: uppercase;
    letter-spacing: 0.1em; margin-bottom: 12px;
    padding-bottom: 6px; border-bottom: 1px solid #21262d;
  }}
  .summary-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px;
  }}
  .summary-card {{
    background: #161b22; border: 1px solid #21262d; border-radius: 6px;
    padding: 12px; text-align: center;
  }}
  .summary-card .value {{ font-size: 1.8em; font-weight: 900; color: #e6edf3; }}
  .summary-card .label {{ font-size: 0.75em; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{
    text-align: left; padding: 8px 12px; background: #161b22;
    color: #8b949e; font-size: 0.8em; text-transform: uppercase;
    letter-spacing: 0.05em; border-bottom: 1px solid #21262d;
  }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; color: #c9d1d9; }}
  .narrative {{
    background: #161b22; border: 1px solid #21262d; border-radius: 6px;
    padding: 16px; font-size: 0.95em; line-height: 1.8; white-space: pre-line;
  }}
  .footer {{
    margin-top: 32px; padding-top: 16px; border-top: 1px solid #21262d;
    font-size: 0.8em; color: #484f58; text-align: center;
  }}
  a {{ color: #00ff41; text-decoration: none; }}
  @media print {{
    body {{ background: white; color: #1a1a1a; }}
    .header {{ border-color: #ddd; background: #f6f8fa; }}
    .section h2 {{ color: #1a1a1a; }}
    table th {{ background: #f6f8fa; color: #1a1a1a; }}
    td {{ color: #1a1a1a; }}
  }}
</style>
</head>
<body>
<div class="header">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;">
    <div>
      <h1>{exec_summary.get('incident_title', 'Incident Report')}</h1>
      <div class="meta">
        Report ID: {metadata.get('report_id', 'N/A')} |
        Generated: {metadata.get('generated_at', datetime.now(timezone.utc).isoformat())} |
        Generator: {metadata.get('generator', 'ThreatTriage')}
      </div>
    </div>
    <div class="severity-badge">{severity}</div>
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <div class="value">{exec_summary.get('total_alerts', 0)}</div>
      <div class="label">Alerts</div>
    </div>
    <div class="summary-card">
      <div class="value">{exec_summary.get('total_iocs', 0)}</div>
      <div class="label">IOCs</div>
    </div>
    <div class="summary-card">
      <div class="value">{len(mitre.get('techniques', []))}</div>
      <div class="label">MITRE Techniques</div>
    </div>
    <div class="summary-card">
      <div class="value">{len(mitre.get('tactics', []))}</div>
      <div class="label">Tactics</div>
    </div>
  </div>
  <div class="narrative">{exec_summary.get('summary', 'No summary available.')}</div>
</div>

{'<div class="section"><h2>MITRE ATT&CK Techniques</h2><table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Detections</th></tr></thead><tbody>' + techniques_html + '</tbody></table></div>' if techniques_html else ''}

{'<div class="section"><h2>Event Timeline</h2><table><thead><tr><th>Timestamp</th><th>Event</th><th>Severity</th><th>Source IP</th></tr></thead><tbody>' + timeline_html + '</tbody></table></div>' if timeline_html else ''}

{'<div class="section"><h2>Remediation Recommendations</h2>' + recs_html + '</div>' if recs_html else ''}

{'<div class="section"><h2>Indicators of Compromise</h2><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>' + iocs_html + '</tbody></table></div>' if iocs_html else ''}

<div class="footer">
  ThreatTriage &mdash; Automated SOC Alert &amp; Log Analysis Engine |
  This report is auto-generated and classified as CONFIDENTIAL
</div>
</body>
</html>"""


def generate_pdf_report(
    report_data: dict[str, Any],
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Generate a PDF report from incident report data.

    Tries WeasyPrint first; falls back to HTML output if unavailable.
    """
    out_dir = output_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    metadata = report_data.get("report_metadata", {})
    report_id = metadata.get("report_id", "unknown")
    html_content = _generate_pdf_html(report_data)

    # Try WeasyPrint
    try:
        from weasyprint import HTML

        pdf_path = out_dir / f"incident_{report_id}.pdf"
        HTML(string=html_content).write_pdf(str(pdf_path))

        logger.info("pdf_report_generated", path=str(pdf_path), engine="weasyprint")

        return {
            "status": "success",
            "format": "pdf",
            "engine": "weasyprint",
            "path": str(pdf_path),
            "filename": pdf_path.name,
            "size_bytes": pdf_path.stat().st_size,
        }
    except ImportError:
        logger.info("weasyprint_not_available", fallback="html")
    except Exception as exc:
        logger.warning("weasyprint_failed", error=str(exc), fallback="html")

    # Fallback: save as print-ready HTML
    html_path = out_dir / f"incident_{report_id}_report.html"
    html_path.write_text(html_content, encoding="utf-8")

    logger.info("pdf_report_generated", path=str(html_path), engine="html_fallback")

    return {
        "status": "success",
        "format": "html",
        "engine": "html_fallback",
        "path": str(html_path),
        "filename": html_path.name,
        "size_bytes": html_path.stat().st_size,
        "note": "Install weasyprint for native PDF output: pip install weasyprint",
    }
