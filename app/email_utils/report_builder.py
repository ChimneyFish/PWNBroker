import os
import sqlalchemy as sa
from html import escape as h
from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "reports",
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#2563eb"),
    "info":     colors.HexColor("#6b7280"),
}


# ── Disk helpers ──────────────────────────────────────────────────────────────

def save_report_to_disk(data: bytes, filename: str) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    return path


def load_report_from_disk(filename: str) -> bytes:
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "rb") as f:
        return f.read()


def delete_report_from_disk(filename: str):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        os.remove(path)


# ── PDF report ────────────────────────────────────────────────────────────────

def build_pdf_report(scans) -> bytes:
    from ..models import ScanResult

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                 fontSize=24, textColor=colors.HexColor("#0f172a"),
                                 spaceAfter=4)
    sub_style   = ParagraphStyle("Sub", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#64748b"))
    h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                 fontSize=14, textColor=colors.HexColor("#1e293b"),
                                 spaceBefore=16)
    body_style  = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9)

    story.append(Paragraph("Vulnerability Scan Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        sub_style,
    ))
    story.append(HRFlowable(width="100%", thickness=2,
                            color=colors.HexColor("#3b82f6"), spaceAfter=12))

    for scan in scans:
        story.append(Paragraph(f"Scan: {scan.name}", h2_style))
        story.append(Paragraph(
            f"Target: {scan.target.host} &nbsp;|&nbsp; Status: {scan.status} &nbsp;|&nbsp; "
            f"Completed: {scan.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan.completed_at else 'N/A'}",
            sub_style,
        ))
        story.append(Spacer(1, 8))

        results = scan.results.filter(
            sa.or_(
                ScanResult.result_type == "vulnerability",
                ScanResult.result_type == "web_check",
            )
        ).order_by(ScanResult.severity).all()

        if not results:
            story.append(Paragraph("No vulnerabilities found.", body_style))
        else:
            table_data = [["Severity", "Title", "Host", "CVSS", "Description"]]
            for r in results:
                table_data.append([
                    r.severity.upper(),
                    (r.title or "")[:50],
                    r.host or "",
                    str(r.cvss_score) if r.cvss_score else "",
                    (r.description or "")[:80],
                ])
            t = Table(table_data,
                      colWidths=[0.7*inch, 1.8*inch, 1.4*inch, 0.6*inch, 2.5*inch])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1e293b")),
                ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)

        story.append(Spacer(1, 16))

    doc.build(story)
    return buf.getvalue()


# ── HTML report ───────────────────────────────────────────────────────────────

def build_html_report(scans) -> str:
    rows = []
    for scan in scans:
        results = scan.results.all()
        for r in results:
            color = {
                "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
                "low": "#2563eb", "info": "#6b7280",
            }.get(r.severity, "#6b7280")
            rows.append(f"""
            <tr>
              <td>{h(scan.name)}</td>
              <td>{h(scan.target.host)}</td>
              <td><span style="color:{color};font-weight:bold">{h(r.severity.upper())}</span></td>
              <td>{h(r.title or '')}</td>
              <td>{h(r.host or '')}</td>
              <td>{h(str(r.cvss_score) if r.cvss_score else '')}</td>
              <td>{h((r.description or '')[:120])}</td>
            </tr>""")

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
body{{font-family:sans-serif;background:#f8fafc;color:#1e293b;padding:32px}}
h1{{color:#0f172a}}table{{border-collapse:collapse;width:100%}}
th{{background:#1e293b;color:#fff;padding:8px 12px;text-align:left}}
td{{padding:7px 12px;border-bottom:1px solid #e2e8f0}}
tr:nth-child(even){{background:#f1f5f9}}
</style></head>
<body>
<h1>Vulnerability Scan Report</h1>
<p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<table>
<thead><tr>
  <th>Scan</th><th>Target</th><th>Severity</th>
  <th>Title</th><th>Host</th><th>CVSS</th><th>Description</th>
</tr></thead>
<tbody>{''.join(rows)}</tbody>
</table></body></html>"""
