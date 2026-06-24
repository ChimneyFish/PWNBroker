import os
import base64
import sqlalchemy as sa
from html import escape as h
from io import BytesIO
from datetime import datetime, timezone
from collections import defaultdict

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, Image, KeepTogether, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, Table, TableStyle,
)

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "reports",
)

LOGO_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "static", "img", "logo.png",
)

# ── Brand palette ─────────────────────────────────────────────────────────────
BRAND   = colors.HexColor("#0bbcd4")
DARK    = colors.HexColor("#0f172a")
SLATE   = colors.HexColor("#475569")
LGRAY   = colors.HexColor("#f1f5f9")
BORDER  = colors.HexColor("#cbd5e1")
GREEN   = colors.HexColor("#15803d")
YELLOW  = colors.HexColor("#b45309")
WHITE   = colors.white

SEV_COLOR = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#2563eb"),
    "info":     colors.HexColor("#6b7280"),
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


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


# ── Shared PDF helpers ────────────────────────────────────────────────────────

def _logo_flowable(target_width=2.0 * inch):
    if not os.path.exists(LOGO_PATH):
        return None
    img = Image(LOGO_PATH)
    aspect = img.imageHeight / img.imageWidth
    img.drawWidth = target_width
    img.drawHeight = target_width * aspect
    return img


def _styles():
    return {
        "cover_title": ParagraphStyle("cover_title", fontSize=28, textColor=DARK,
                                      fontName="Helvetica-Bold", spaceAfter=6,
                                      alignment=TA_CENTER, leading=34),
        "cover_sub":   ParagraphStyle("cover_sub", fontSize=12, textColor=SLATE,
                                      fontName="Helvetica", spaceAfter=4,
                                      alignment=TA_CENTER),
        "cover_meta":  ParagraphStyle("cover_meta", fontSize=9, textColor=SLATE,
                                      fontName="Helvetica", spaceAfter=2,
                                      alignment=TA_CENTER),
        "toc_head":    ParagraphStyle("toc_head", fontSize=16, textColor=DARK,
                                      fontName="Helvetica-Bold", spaceAfter=12),
        "toc_item":    ParagraphStyle("toc_item", fontSize=10, textColor=SLATE,
                                      fontName="Helvetica", leading=18, leftIndent=8),
        "toc_sub":     ParagraphStyle("toc_sub", fontSize=9, textColor=SLATE,
                                      fontName="Helvetica", leading=16, leftIndent=24),
        "h2":          ParagraphStyle("h2", fontSize=14, textColor=BRAND,
                                      fontName="Helvetica-Bold",
                                      spaceBefore=14, spaceAfter=4),
        "h3":          ParagraphStyle("h3", fontSize=11, textColor=DARK,
                                      fontName="Helvetica-Bold",
                                      spaceBefore=8, spaceAfter=2),
        "body":        ParagraphStyle("body", fontSize=9, textColor=DARK,
                                      fontName="Helvetica", leading=13),
        "small":       ParagraphStyle("small", fontSize=7.5, textColor=SLATE,
                                      fontName="Helvetica", leading=11),
    }


def _page_callback(title):
    """Stamp logo header + page footer on every page."""
    def _draw(canvas, doc):
        canvas.saveState()
        pw = letter[0]
        if os.path.exists(LOGO_PATH):
            canvas.drawImage(
                LOGO_PATH,
                doc.leftMargin, letter[1] - doc.topMargin + 6,
                width=0.9 * inch, height=0.9 * inch * (262 / 480),
                preserveAspectRatio=True, mask="auto",
            )
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(SLATE)
        canvas.drawRightString(pw - doc.rightMargin,
                               letter[1] - doc.topMargin + 10, title)
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, letter[1] - doc.topMargin + 4,
                    pw - doc.rightMargin, letter[1] - doc.topMargin + 4)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(SLATE)
        canvas.drawString(doc.leftMargin, 0.45 * inch,
                          "PwnBroker — CONFIDENTIAL — For Authorized Use Only")
        canvas.drawRightString(pw - doc.rightMargin, 0.45 * inch,
                               f"Page {doc.page}")
        canvas.setStrokeColor(BORDER)
        canvas.line(doc.leftMargin, 0.6 * inch, pw - doc.rightMargin, 0.6 * inch)
        canvas.restoreState()
    return _draw


def _toc_link(dest, label, level=0):
    S = _styles()
    style = S["toc_sub"] if level > 0 else S["toc_item"]
    bullet = "  ›  " if level > 0 else "▸  "
    return Paragraph(
        f'{bullet}<link destination="{dest}" color="#0bbcd4">{label}</link>',
        style,
    )


def _anchor(name):
    return Paragraph(f'<a name="{name}"/>', ParagraphStyle(
        "anc", fontSize=0.01, spaceAfter=0, spaceBefore=0, leading=0.01))


def _cover_page(story, S, title, subtitle, meta_lines):
    story.append(Spacer(1, 0.6 * inch))
    logo = _logo_flowable(2.4 * inch)
    if logo:
        logo.hAlign = "CENTER"
        story.append(logo)
    story.append(Spacer(1, 0.3 * inch))
    bar = Table([[""]], colWidths=[3 * inch], rowHeights=[3])
    bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BRAND),
                              ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    bar.hAlign = "CENTER"
    story.append(bar)
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(title, S["cover_title"]))
    if subtitle:
        story.append(Paragraph(subtitle, S["cover_sub"]))
    story.append(Spacer(1, 0.15 * inch))
    for line in meta_lines:
        story.append(Paragraph(line, S["cover_meta"]))
    story.append(PageBreak())


def _stat_grid(rows_of_items, col_count=4):
    """Render a grid of (label, value, color) tuples."""
    flat = [item for row in rows_of_items for item in row]
    while len(flat) % col_count:
        flat.append(None)
    paragraphs = []
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for i, item in enumerate(flat):
        row_idx = i // col_count
        col_idx = i % col_count
        if item is None:
            paragraphs.append("")
        else:
            label, value, col = item
            hex_c = "#" + col.hexval()[2:]
            p = Paragraph(
                f'<font color="{hex_c}"><b><font size="16">{value}</font></b></font>'
                f'<br/><font size="7" color="#475569">{label}</font>',
                ParagraphStyle("sg", alignment=TA_CENTER, leading=18, fontSize=9),
            )
            paragraphs.append(p)
            style_cmds.append(
                ("BACKGROUND", (col_idx, row_idx), (col_idx, row_idx), LGRAY))

    grid_rows = [paragraphs[i:i+col_count] for i in range(0, len(paragraphs), col_count)]
    cw = (6.5 * inch) / col_count
    t = Table(grid_rows, colWidths=[cw] * col_count)
    t.setStyle(TableStyle(style_cmds))
    return t


def _std_table_style():
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LGRAY]),
        ("GRID",          (0, 0), (-1, -1), 0.3, BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("LINEBELOW",     (0, 0), (-1, 0), 1, BRAND),
    ])


def _sev_para(sev, style_name="small"):
    S = _styles()
    col = SEV_COLOR.get((sev or "info").lower(), SLATE)
    hex_c = "#" + col.hexval()[2:]
    return Paragraph(
        f'<font color="{hex_c}"><b>{(sev or "info").upper()}</b></font>',
        ParagraphStyle(style_name + "_sc", fontSize=8, alignment=TA_CENTER),
    )


# ── Scan PDF report ───────────────────────────────────────────────────────────

def build_pdf_report(scans) -> bytes:
    from ..models import ScanResult

    buf = BytesIO()
    cb = _page_callback("Vulnerability Scan Report")
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=1.1 * inch, bottomMargin=0.75 * inch)
    S = _styles()
    story = []
    now_str = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    totals = defaultdict(int)
    for scan in scans:
        for sev in SEV_ORDER:
            totals[sev] += scan.results.filter_by(
                result_type="vulnerability", severity=sev).count()
    total_vulns = sum(totals.values())
    targets_str = ", ".join(s.target.host for s in scans)

    # ── Cover ─────────────────────────────────────────────────────────────────
    _cover_page(story, S,
                "Vulnerability Scan Report",
                "Security Assessment Findings",
                [
                    f"Generated: {now_str}",
                    f"Target(s): {targets_str}",
                    f"Total Scans: {len(scans)}  |  Total Findings: {total_vulns}",
                    "Classification: CONFIDENTIAL",
                ])

    # ── TOC ───────────────────────────────────────────────────────────────────
    story.append(_anchor("toc"))
    story.append(Paragraph("Table of Contents", S["toc_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND, spaceAfter=8))
    for dest, label in [
        ("sec_exec",  "1. Executive Summary"),
        ("sec_scans", "2. Scan Overview"),
        ("sec_vulns", "3. Vulnerability Findings"),
        ("sec_remed", "4. Remediation Recommendations"),
    ]:
        story.append(_toc_link(dest, label))
    story.append(PageBreak())

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    story.append(_anchor("sec_exec"))
    story.append(Paragraph("1. Executive Summary", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))

    sev_items = [(s.upper(), str(totals[s]), SEV_COLOR.get(s, SLATE)) for s in SEV_ORDER]
    story.append(_stat_grid([sev_items[:4], sev_items[4:]]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"This report covers <b>{len(scans)}</b> completed scan(s) against "
        f"<b>{targets_str}</b>. A total of <b>{total_vulns}</b> findings were identified. "
        "Immediate attention is recommended for Critical and High severity findings.",
        S["body"]))
    story.append(Spacer(1, 16))

    # ── 2. Scan Overview ──────────────────────────────────────────────────────
    story.append(_anchor("sec_scans"))
    story.append(Paragraph("2. Scan Overview", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))

    scan_rows = [["Scan Name", "Target", "Type", "Completed", "Findings"]]
    for scan in scans:
        cnt  = scan.results.filter_by(result_type="vulnerability").count()
        crit = scan.results.filter_by(result_type="vulnerability", severity="critical").count()
        fstr = f"{cnt} total" + (f" ({crit} critical)" if crit else "")
        scan_rows.append([
            scan.name, scan.target.host, scan.scan_type,
            scan.completed_at.strftime("%Y-%m-%d %H:%M") if scan.completed_at else "—",
            fstr,
        ])
    st = Table(scan_rows, colWidths=[1.8*inch, 1.4*inch, 0.8*inch, 1.4*inch, 1.1*inch])
    st.setStyle(_std_table_style())
    story.append(st)
    story.append(Spacer(1, 16))

    # ── 3. Vulnerability Findings ─────────────────────────────────────────────
    story.append(_anchor("sec_vulns"))
    story.append(Paragraph("3. Vulnerability Findings", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))

    for scan in scans:
        story.append(Paragraph(f"Scan: {scan.name}", S["h3"]))
        story.append(Paragraph(
            f"Target: <b>{scan.target.host}</b>  |  "
            f"Completed: {scan.completed_at.strftime('%Y-%m-%d') if scan.completed_at else 'N/A'}",
            S["small"]))
        story.append(Spacer(1, 6))

        results = scan.results.filter(
            sa.or_(
                ScanResult.result_type == "vulnerability",
                ScanResult.result_type == "web_check",
            )
        ).order_by(
            sa.case(
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
                value=ScanResult.severity,
            )
        ).all()

        if not results:
            story.append(Paragraph("No vulnerabilities found in this scan.", S["body"]))
        else:
            tbl_data = [["Sev", "Title", "Host", "CVE / CVSS", "Description"]]
            for r in results:
                cve_str = (r.cve_id or "") + (f"\n{r.cvss_score}" if r.cvss_score else "")
                tbl_data.append([
                    _sev_para(r.severity),
                    Paragraph(h(r.title or "")[:70], S["small"]),
                    Paragraph(h(r.host or ""), S["small"]),
                    Paragraph(h(cve_str), S["small"]),
                    Paragraph(h((r.description or "")[:100]), S["small"]),
                ])
            t = Table(tbl_data,
                      colWidths=[0.55*inch, 1.9*inch, 1.1*inch, 0.85*inch, 2.1*inch])
            t.setStyle(_std_table_style())
            story.append(t)
        story.append(Spacer(1, 14))

    # ── 4. Remediation ────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(_anchor("sec_remed"))
    story.append(Paragraph("4. Remediation Recommendations", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))

    remed_data = []
    for scan in scans:
        for r in scan.results.filter(
            sa.and_(
                ScanResult.result_type == "vulnerability",
                ScanResult.remediation.isnot(None),
                ScanResult.remediation != "",
            )
        ).order_by(
            sa.case({"critical": 0, "high": 1, "medium": 2, "low": 3},
                    value=ScanResult.severity)
        ).all():
            remed_data.append((r.severity, r.title, r.host, r.remediation))

    if not remed_data:
        story.append(Paragraph(
            "No specific remediation guidance was captured. "
            "Refer to CVE databases and vendor advisories for each finding.", S["body"]))
    else:
        for sev, title, host_val, remed in remed_data:
            col = SEV_COLOR.get((sev or "info").lower(), SLATE)
            hex_c = "#" + col.hexval()[2:]
            block = KeepTogether([
                Table([[
                    Paragraph(f'<font color="{hex_c}"><b>{(sev or "info").upper()}</b></font>',
                              ParagraphStyle("rs", fontSize=8, alignment=TA_CENTER)),
                    Paragraph(f"<b>{h(title or '')}</b>  —  {h(host_val or '')}", S["body"]),
                ]], colWidths=[0.65*inch, 5.85*inch],
                   style=TableStyle([
                       ("BACKGROUND", (0, 0), (-1, -1), LGRAY),
                       ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                       ("TOPPADDING", (0, 0), (-1, -1), 4),
                       ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                       ("LEFTPADDING", (0, 0), (-1, -1), 6),
                       ("LINEABOVE", (0, 0), (-1, 0), 0.5, BORDER),
                   ])),
                Table([[Paragraph(h(remed[:300]), S["small"])]],
                      colWidths=[6.5*inch],
                      style=TableStyle([
                          ("LEFTPADDING", (0, 0), (-1, -1), 14),
                          ("TOPPADDING", (0, 0), (-1, -1), 3),
                          ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                      ])),
            ])
            story.append(block)

    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    return buf.getvalue()


# ── HTML report ───────────────────────────────────────────────────────────────

def _logo_base64() -> str:
    if not os.path.exists(LOGO_PATH):
        return ""
    with open(LOGO_PATH, "rb") as f:
        return "data:image/png;base64," + base64.b64encode(f.read()).decode()


def build_html_report(scans) -> str:
    from ..models import ScanResult

    logo_src = _logo_base64()
    now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    totals = defaultdict(int)
    for scan in scans:
        for sev in SEV_ORDER:
            totals[sev] += scan.results.filter_by(
                result_type="vulnerability", severity=sev).count()
    total_vulns = sum(totals.values())

    scan_sections = []
    for scan in scans:
        results = scan.results.filter(
            sa.or_(
                ScanResult.result_type == "vulnerability",
                ScanResult.result_type == "web_check",
            )
        ).order_by(
            sa.case(
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
                value=ScanResult.severity,
            )
        ).all()

        rows_html = ""
        for r in results:
            sc = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
                  "low": "#2563eb", "info": "#6b7280"}.get(
                      (r.severity or "info").lower(), "#6b7280")
            rows_html += (
                f"<tr>"
                f'<td><span class="badge" style="background:{sc}">'
                f'{h((r.severity or "info").upper())}</span></td>'
                f"<td>{h(r.title or '')}</td>"
                f"<td>{h(r.host or '')}</td>"
                f"<td>{h(r.cve_id or '')}</td>"
                f"<td>{h(str(r.cvss_score) if r.cvss_score else '')}</td>"
                f'<td class="desc">{h((r.description or "")[:200])}</td>'
                f"</tr>"
            )

        sev_pills = " ".join(
            f'<span class="pill pill-{sev}">{cnt} {sev.upper()}</span>'
            for sev in SEV_ORDER
            if (cnt := scan.results.filter_by(
                result_type="vulnerability", severity=sev).count()) > 0
        )

        vuln_table = (
            "<table><thead><tr>"
            "<th>Severity</th><th>Title</th><th>Host</th>"
            "<th>CVE</th><th>CVSS</th><th>Description</th>"
            f"</tr></thead><tbody>{rows_html}</tbody></table>"
            if results else
            '<p class="no-findings">&#10003; No vulnerabilities found in this scan.</p>'
        )

        scan_sections.append(
            f'<section id="scan_{scan.id}" class="scan-section">'
            f"<h2><span class='scan-icon'>&#9889;</span>{h(scan.name)}</h2>"
            f'<div class="scan-meta">'
            f"<span>&#127919; {h(scan.target.host)}</span>"
            f"<span>&#128197; {scan.completed_at.strftime('%Y-%m-%d %H:%M') if scan.completed_at else '—'}</span>"
            f"<span>&#128269; {scan.scan_type}</span>"
            f"</div>"
            f'<div class="sev-pills">{sev_pills}</div>'
            f"{vuln_table}"
            f"</section>"
        )

    toc_items = "\n".join(
        f'<li><a href="#scan_{s.id}">{h(s.name)} &mdash; {h(s.target.host)}</a></li>'
        for s in scans
    )

    sev_summary = "".join(
        f'<div class="stat-box">'
        f'<div class="stat-val" style="color:{c}">{totals[sev]}</div>'
        f'<div class="stat-lbl">{sev.upper()}</div>'
        f"</div>"
        for sev, c in [("critical","#dc2626"),("high","#ea580c"),
                       ("medium","#d97706"),("low","#2563eb"),("info","#6b7280")]
    )

    logo_img = (
        f'<img src="{logo_src}" alt="PwnBroker" class="report-logo">'
        if logo_src else
        '<div class="report-logo-text">PwnBroker</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PwnBroker &mdash; Vulnerability Scan Report</title>
<style>
:root{{--brand:#0bbcd4;--dark:#0f172a;--slate:#475569;--border:#cbd5e1;
      --lgray:#f8fafc;--green:#15803d}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Inter,sans-serif;background:var(--lgray);
     color:var(--dark);font-size:14px;line-height:1.5}}
.cover{{background:var(--dark);color:#fff;padding:60px 48px 48px;
        display:flex;flex-direction:column;align-items:center;text-align:center}}
.report-logo{{height:72px;margin-bottom:24px}}
.report-logo-text{{font-size:28px;font-weight:700;color:var(--brand);margin-bottom:24px}}
.accent-bar{{width:160px;height:3px;background:var(--brand);margin:16px auto}}
.cover h1{{font-size:28px;font-weight:700;margin-bottom:8px}}
.cover .subtitle{{color:#94a3b8;font-size:14px;margin-bottom:6px}}
.cover .meta-line{{color:#64748b;font-size:12px;margin-top:4px}}
.stat-row{{display:flex;gap:16px;justify-content:center;margin:32px 0 0;flex-wrap:wrap}}
.stat-box{{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);
           border-radius:8px;padding:16px 24px;text-align:center;min-width:90px}}
.stat-val{{font-size:28px;font-weight:700;line-height:1}}
.stat-lbl{{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-top:4px}}
.container{{max-width:1100px;margin:0 auto;padding:32px 24px}}
.toc{{background:#fff;border:1px solid var(--border);border-radius:10px;
      padding:24px 32px;margin-bottom:32px;box-shadow:0 1px 4px rgba(0,0,0,.05)}}
.toc h2{{font-size:16px;color:var(--brand);margin-bottom:16px;font-weight:700}}
.toc ol{{padding-left:20px}}.toc li{{margin-bottom:8px}}
.toc a{{color:var(--brand);text-decoration:none;font-size:14px}}
.toc a:hover{{text-decoration:underline}}
.scan-section{{background:#fff;border:1px solid var(--border);border-radius:10px;
               padding:28px 32px;margin-bottom:28px;box-shadow:0 1px 4px rgba(0,0,0,.05)}}
.scan-section h2{{font-size:18px;font-weight:700;color:var(--dark);
                  border-bottom:2px solid var(--brand);padding-bottom:10px;
                  margin-bottom:12px;display:flex;align-items:center;gap:8px}}
.scan-meta{{display:flex;gap:20px;color:var(--slate);font-size:12px;
            margin-bottom:12px;flex-wrap:wrap}}
.sev-pills{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}}
.pill{{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;color:#fff}}
.pill-critical{{background:#dc2626}}.pill-high{{background:#ea580c}}
.pill-medium{{background:#d97706}}.pill-low{{background:#2563eb}}
.pill-info{{background:#6b7280}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}
thead tr{{background:var(--dark);color:#fff}}
th{{padding:10px 12px;text-align:left;font-size:11px;text-transform:uppercase;
    letter-spacing:.06em;font-weight:600}}
td{{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
tbody tr:nth-child(even){{background:#f8fafc}}
tbody tr:hover{{background:#f0f9ff}}
.badge{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;
        color:#fff;white-space:nowrap}}
.desc{{color:var(--slate);font-size:12px;max-width:300px}}
.no-findings{{color:var(--green);padding:16px 0;font-size:14px}}
.report-footer{{text-align:center;padding:32px;color:var(--slate);
                font-size:11px;border-top:1px solid var(--border);margin-top:16px}}
@media print{{.cover{{break-after:page}}.scan-section{{break-inside:avoid}}
              .toc{{break-after:page}}}}
</style>
</head>
<body>
<div class="cover">
  {logo_img}
  <div class="accent-bar"></div>
  <h1>Vulnerability Scan Report</h1>
  <div class="subtitle">Security Assessment Findings</div>
  <div class="meta-line">Generated: {now_str}</div>
  <div class="meta-line">Scans Covered: {len(scans)} &nbsp;&middot;&nbsp; Total Findings: {total_vulns}</div>
  <div class="meta-line" style="margin-top:8px;color:#ef4444;font-weight:600">
    &#128274; CONFIDENTIAL &mdash; For Authorized Personnel Only
  </div>
  <div class="stat-row">{sev_summary}</div>
</div>
<div class="container">
  <div class="toc">
    <h2>&#128196; Table of Contents</h2>
    <ol>{toc_items}</ol>
  </div>
  {''.join(scan_sections)}
  <div class="report-footer">
    PwnBroker Security Platform &nbsp;&middot;&nbsp; Report generated {now_str}
    &nbsp;&middot;&nbsp; CONFIDENTIAL &mdash; For Authorized Use Only
  </div>
</div>
</body>
</html>"""


# ── Technical Overview PDF ────────────────────────────────────────────────────

def build_tech_overview_pdf() -> bytes:
    from ..models import Scan, ScanResult, VulnTicket, Asset

    buf = BytesIO()
    cb  = _page_callback("Technical Vulnerability Management Overview")
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=1.1*inch, bottomMargin=0.75*inch)
    S = _styles()
    story = []
    now_str = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    # ── Data ──────────────────────────────────────────────────────────────────
    all_results = ScanResult.query.join(Scan).filter(
        Scan.status == "done",
        ScanResult.result_type == "vulnerability",
    ).all()

    sev_counts = defaultdict(int)
    for r in all_results:
        sev_counts[(r.severity or "info").lower()] += 1
    total_vulns = len(all_results)

    cve_freq, cve_sev = defaultdict(int), {}
    for r in all_results:
        if r.cve_id:
            cve_freq[r.cve_id] += 1
            if r.cve_id not in cve_sev or \
               SEV_ORDER.index((r.severity or "info").lower()) < \
               SEV_ORDER.index(cve_sev[r.cve_id]):
                cve_sev[r.cve_id] = (r.severity or "info").lower()
    top_cves = sorted(cve_freq.items(), key=lambda x: -x[1])[:15]

    svc_counts = defaultdict(int)
    for r in all_results:
        if r.service:
            svc_counts[r.service] += 1
    top_svcs = sorted(svc_counts.items(), key=lambda x: -x[1])[:10]

    tickets = VulnTicket.query.all()
    sla_stats    = defaultdict(int)
    ticket_status = defaultdict(int)
    for t in tickets:
        sla_stats[t.sla_status] += 1
        ticket_status[t.status] += 1

    dep_results = ScanResult.query.join(Scan).filter(
        Scan.status == "done", Scan.scan_type == "osv",
        ScanResult.result_type == "vulnerability",
    ).all()
    dep_sev = defaultdict(int)
    for r in dep_results:
        dep_sev[(r.severity or "info").lower()] += 1

    asset_count   = Asset.query.count()
    scanned_count = Scan.query.filter_by(status="done").count()

    # ── Cover ─────────────────────────────────────────────────────────────────
    _cover_page(story, S,
                "Technical Vulnerability\nManagement Overview",
                "Comprehensive Security Posture Analysis",
                [
                    f"Generated: {now_str}",
                    f"Assets Inventoried: {asset_count}  |  Completed Scans: {scanned_count}",
                    f"Total Vulnerabilities Tracked: {total_vulns}",
                    "Classification: CONFIDENTIAL",
                ])

    # ── TOC ───────────────────────────────────────────────────────────────────
    story.append(_anchor("toc"))
    story.append(Paragraph("Table of Contents", S["toc_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND, spaceAfter=8))
    for dest, label in [
        ("sec_overview", "1. Vulnerability Overview"),
        ("sec_sev",      "2. Severity Distribution"),
        ("sec_cves",     "3. Top CVEs Identified"),
        ("sec_svcs",     "4. Exposed Services Analysis"),
        ("sec_dep",      "5. Dependency Vulnerabilities"),
        ("sec_sla",      "6. SLA & Remediation Status"),
        ("sec_rec",      "7. Technical Recommendations"),
    ]:
        story.append(_toc_link(dest, label))
    story.append(PageBreak())

    # ── 1. Overview ───────────────────────────────────────────────────────────
    story.append(_anchor("sec_overview"))
    story.append(Paragraph("1. Vulnerability Overview", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    items = [
        ("CRITICAL", str(sev_counts["critical"]), SEV_COLOR["critical"]),
        ("HIGH",     str(sev_counts["high"]),     SEV_COLOR["high"]),
        ("MEDIUM",   str(sev_counts["medium"]),   SEV_COLOR["medium"]),
        ("LOW",      str(sev_counts["low"]),      SEV_COLOR["low"]),
        ("INFO",     str(sev_counts["info"]),     SEV_COLOR["info"]),
        ("TOTAL",    str(total_vulns),            BRAND),
    ]
    story.append(_stat_grid([items[:3], items[3:]]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"PwnBroker has completed <b>{scanned_count}</b> scans across "
        f"<b>{asset_count}</b> inventoried assets with <b>{total_vulns}</b> total findings. "
        "Critical and High findings require remediation within 1 and 7 days respectively.",
        S["body"]))
    story.append(Spacer(1, 16))

    # ── 2. Severity Distribution ──────────────────────────────────────────────
    story.append(_anchor("sec_sev"))
    story.append(Paragraph("2. Severity Distribution", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    sla_map = {"critical": "1 day", "high": "7 days", "medium": "30 days",
               "low": "90 days", "info": "180 days"}
    sev_rows = [["Severity", "Count", "% of Total", "SLA Window"]]
    for sev in SEV_ORDER:
        cnt = sev_counts[sev]
        pct = f"{cnt/total_vulns*100:.1f}%" if total_vulns else "0%"
        sev_rows.append([_sev_para(sev), str(cnt), pct, sla_map[sev]])
    dt = Table(sev_rows, colWidths=[1.2*inch, 0.8*inch, 1*inch, 1.2*inch])
    dt.setStyle(_std_table_style())
    story.append(dt)
    story.append(Spacer(1, 16))

    # ── 3. Top CVEs ───────────────────────────────────────────────────────────
    story.append(_anchor("sec_cves"))
    story.append(Paragraph("3. Top CVEs Identified", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    if top_cves:
        cve_rows = [["CVE ID", "Occurrences", "Severity", "Priority"]]
        for cve_id, cnt in top_cves:
            sev = cve_sev.get(cve_id, "info")
            priority = ("Immediate" if sev == "critical" else "Urgent" if sev == "high"
                        else "Scheduled" if sev == "medium" else "Planned")
            cve_rows.append([
                Paragraph(f"<b>{h(cve_id)}</b>", S["body"]),
                str(cnt), _sev_para(sev), priority,
            ])
        ct = Table(cve_rows, colWidths=[1.8*inch, 1*inch, 1*inch, 2*inch])
        ct.setStyle(_std_table_style())
        story.append(ct)
    else:
        story.append(Paragraph("No CVE identifiers recorded in current scan data.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 4. Services ───────────────────────────────────────────────────────────
    story.append(_anchor("sec_svcs"))
    story.append(Paragraph("4. Exposed Services Analysis", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    if top_svcs:
        HIGH_RISK = {"telnet", "ftp", "vnc", "rdp", "smb", "snmp"}
        svc_rows = [["Service", "Vulnerability Count", "Risk Note"]]
        for svc, cnt in top_svcs:
            risk = "Legacy / High-Risk" if svc.lower() in HIGH_RISK else "Review Required"
            svc_rows.append([h(svc), str(cnt), risk])
        svct = Table(svc_rows, colWidths=[2*inch, 1.5*inch, 3*inch])
        svct.setStyle(_std_table_style())
        story.append(svct)
    else:
        story.append(Paragraph("No service data captured in current scans.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 5. Dependency Vulns ───────────────────────────────────────────────────
    story.append(_anchor("sec_dep"))
    story.append(Paragraph("5. Dependency Vulnerabilities", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    dep_total = len(dep_results)
    if dep_total:
        story.append(Paragraph(
            f"<b>{dep_total}</b> dependency vulnerabilities found across OSV scans.", S["body"]))
        story.append(Spacer(1, 6))
        dep_rows = [["Severity", "Count"]]
        for sev in SEV_ORDER:
            if dep_sev[sev]:
                dep_rows.append([_sev_para(sev), str(dep_sev[sev])])
        dt2 = Table(dep_rows, colWidths=[1.5*inch, 0.8*inch])
        dt2.setStyle(_std_table_style())
        story.append(dt2)
    else:
        story.append(Paragraph("No dependency (OSV) scan results found.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 6. SLA & Remediation ──────────────────────────────────────────────────
    story.append(_anchor("sec_sla"))
    story.append(Paragraph("6. SLA & Remediation Status", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    if tickets:
        rem_items = [
            ("OVERDUE",  str(sla_stats.get("overdue", 0)),  SEV_COLOR["critical"]),
            ("DUE SOON", str(sla_stats.get("due_soon", 0)), SEV_COLOR["medium"]),
            ("ON TRACK", str(sla_stats.get("on_track", 0)), GREEN),
            ("RESOLVED", str(sla_stats.get("resolved", 0)), BRAND),
        ]
        story.append(_stat_grid([rem_items]))
        story.append(Spacer(1, 10))
        status_rows = [["Ticket Status", "Count", "% of Total"]]
        total_t = len(tickets)
        for status, cnt in sorted(ticket_status.items(), key=lambda x: -x[1]):
            status_rows.append([
                status.replace("_", " ").title(),
                str(cnt),
                f"{cnt/total_t*100:.1f}%",
            ])
        stt = Table(status_rows, colWidths=[1.8*inch, 0.8*inch, 0.8*inch])
        stt.setStyle(_std_table_style())
        story.append(stt)
    else:
        story.append(Paragraph("No vulnerability tickets created yet.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 7. Recommendations ────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(_anchor("sec_rec"))
    story.append(Paragraph("7. Technical Recommendations", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8))

    recs = []
    if sev_counts["critical"] > 0:
        recs.append(("IMMEDIATE", SEV_COLOR["critical"],
            f"Remediate all {sev_counts['critical']} Critical findings within 24 hours. "
            "Patch or apply compensating controls without delay."))
    if sev_counts["high"] > 0:
        recs.append(("URGENT", SEV_COLOR["high"],
            f"Address {sev_counts['high']} High severity findings within 7 days. "
            "Prioritize by CVSS score and EPSS exploitation likelihood."))
    if sla_stats.get("overdue", 0) > 0:
        recs.append(("SLA BREACH", SEV_COLOR["critical"],
            f"{sla_stats['overdue']} tickets are past SLA. "
            "Escalate to asset owners and obtain accepted-risk approvals or emergency patches."))
    if dep_total > 0:
        recs.append(("DEPENDENCIES", SEV_COLOR["medium"],
            f"{dep_total} vulnerable dependencies detected. Update packages, enforce lockfile "
            "auditing in CI/CD, and add SCA gates to build pipelines."))
    if any(svc.lower() in {"telnet", "ftp", "snmp"} for svc, _ in top_svcs):
        recs.append(("LEGACY PROTOCOLS", SEV_COLOR["high"],
            "Unencrypted legacy protocols detected. Replace Telnet/FTP/SNMP v1-v2 with "
            "SSH/SFTP/SNMPv3 and disable legacy listeners immediately."))
    recs.append(("CONTINUOUS SCANNING", BRAND,
        "Maintain daily scanning for critical assets and weekly for standard hosts. "
        "Integrate scanning into CI/CD for all new deployments."))

    for priority, col, text in recs:
        hex_c = "#" + col.hexval()[2:]
        block = KeepTogether([
            Table([[
                Paragraph(f'<font color="{hex_c}"><b>{priority}</b></font>',
                          ParagraphStyle("rp", fontSize=8, alignment=TA_CENTER)),
                Paragraph(text, S["body"]),
            ]], colWidths=[0.9*inch, 5.6*inch],
               style=TableStyle([
                   ("BACKGROUND", (0, 0), (-1, -1), LGRAY),
                   ("VALIGN", (0, 0), (-1, -1), "TOP"),
                   ("TOPPADDING", (0, 0), (-1, -1), 6),
                   ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                   ("LEFTPADDING", (0, 0), (-1, -1), 8),
                   ("LINEABOVE", (0, 0), (-1, 0), 0.5, BORDER),
               ])),
        ])
        story.append(block)
        story.append(Spacer(1, 4))

    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    return buf.getvalue()


# ── Executive Summary PDF ─────────────────────────────────────────────────────

def build_executive_summary_pdf() -> bytes:
    from ..models import (
        Scan, ScanResult, VulnTicket, Asset,
        ComplianceFramework, RiskEntry, Policy,
    )

    buf = BytesIO()
    cb  = _page_callback("Executive Security Summary")
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=1.1*inch, bottomMargin=0.75*inch)
    S = _styles()
    story = []
    now_str = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

    # ── Data ──────────────────────────────────────────────────────────────────
    completed_scans = Scan.query.filter_by(status="done").all()
    all_vulns = ScanResult.query.join(Scan).filter(
        Scan.status == "done", ScanResult.result_type == "vulnerability",
    ).all()
    sev_counts = defaultdict(int)
    for r in all_vulns:
        sev_counts[(r.severity or "info").lower()] += 1

    tickets       = VulnTicket.query.all()
    open_tickets  = [t for t in tickets if not t.is_resolved]
    overdue       = [t for t in open_tickets if t.sla_status == "overdue"]
    patched       = [t for t in tickets if t.status == "patched"]
    sla_stat_cnt  = defaultdict(int)
    for t in tickets:
        sla_stat_cnt[t.sla_status] += 1

    asset_count   = Asset.query.count()
    active_assets = Asset.query.filter_by(status="active").count()

    frameworks    = ComplianceFramework.query.all()
    all_risks     = RiskEntry.query.all()
    open_risks    = [r for r in all_risks if r.is_open]
    critical_risks = [r for r in open_risks if r.risk_level == "critical"]
    risk_lvl_cnt  = defaultdict(int)
    for r in open_risks:
        risk_lvl_cnt[r.risk_level] += 1

    policies        = Policy.query.all()
    active_policies = [p for p in policies if p.status == "active"]
    draft_policies  = [p for p in policies if p.status == "draft"]

    # Compliance scores
    fw_scores = []
    for fw in frameworks:
        controls = fw.controls.all()
        total = len(controls)
        if total == 0:
            continue
        compliant = sum(1 for c in controls
                        if c.assessment and c.assessment.status == "compliant")
        na = sum(1 for c in controls
                 if c.assessment and c.assessment.status == "not_applicable")
        score = round(compliant / max(total - na, 1) * 100)
        fw_scores.append((fw.name, score, compliant, total - na))

    overall_compliance = (
        round(sum(s for _, s, _, _ in fw_scores) / len(fw_scores))
        if fw_scores else None
    )

    # Posture score
    posture = 100
    posture -= min(sev_counts["critical"] * 8, 40)
    posture -= min(sev_counts["high"] * 3, 20)
    posture -= min(len(overdue) * 5, 20)
    posture -= min(len(critical_risks) * 5, 15)
    posture = max(0, posture)
    grade = ("A" if posture >= 90 else "B" if posture >= 75 else
             "C" if posture >= 60 else "D" if posture >= 45 else "F")
    posture_col = (GREEN if posture >= 75 else
                   YELLOW if posture >= 50 else SEV_COLOR["critical"])

    # ── Cover ─────────────────────────────────────────────────────────────────
    _cover_page(story, S,
                "Executive Security Summary",
                "Enterprise Security Posture & Compliance Report",
                [
                    f"Report Period: Through {now_str}",
                    f"Assets: {active_assets} active  |  Scans Completed: {len(completed_scans)}",
                    f"Open Vulnerabilities: {len(open_tickets)}  |  Overdue SLAs: {len(overdue)}",
                    "Classification: CONFIDENTIAL — EXECUTIVE DISTRIBUTION",
                ])

    # ── TOC ───────────────────────────────────────────────────────────────────
    story.append(_anchor("toc"))
    story.append(Paragraph("Table of Contents", S["toc_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND, spaceAfter=8))
    for dest, label in [
        ("sec_posture",    "1. Security Posture Overview"),
        ("sec_vulnsumm",   "2. Vulnerability Summary"),
        ("sec_compliance", "3. Compliance Standing"),
        ("sec_risk",       "4. Risk Register Summary"),
        ("sec_remediation","5. Remediation & SLA Performance"),
        ("sec_governance", "6. Policy & Governance Status"),
        ("sec_audit",      "7. Audit Readiness Assessment"),
        ("sec_exec_rec",   "8. Executive Recommendations"),
    ]:
        story.append(_toc_link(dest, label))
    story.append(PageBreak())

    # ── 1. Posture ────────────────────────────────────────────────────────────
    story.append(_anchor("sec_posture"))
    story.append(Paragraph("1. Security Posture Overview", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    posture_items = [
        ("POSTURE SCORE", f"{posture}/100", posture_col),
        ("GRADE",         grade,            posture_col),
        ("ACTIVE ASSETS", str(active_assets), BRAND),
        ("SCANS DONE",    str(len(completed_scans)), BRAND),
    ]
    story.append(_stat_grid([posture_items]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"Overall security posture score: <b>{posture}/100</b> (Grade: <b>{grade}</b>). "
        "Derived from active vulnerability exposure, SLA adherence, and risk register status. "
        + ("Immediate executive action is required." if posture < 60
           else "The security program is progressing with continued improvement recommended."),
        S["body"]))
    story.append(Spacer(1, 16))

    # ── 2. Vulnerability Summary ──────────────────────────────────────────────
    story.append(_anchor("sec_vulnsumm"))
    story.append(Paragraph("2. Vulnerability Summary", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    vuln_items = [
        ("CRITICAL", str(sev_counts["critical"]), SEV_COLOR["critical"]),
        ("HIGH",     str(sev_counts["high"]),     SEV_COLOR["high"]),
        ("MEDIUM",   str(sev_counts["medium"]),   SEV_COLOR["medium"]),
        ("LOW",      str(sev_counts["low"]),      SEV_COLOR["low"]),
        ("OPEN",     str(len(open_tickets)),      SEV_COLOR["high"]),
        ("PATCHED",  str(len(patched)),           GREEN),
    ]
    story.append(_stat_grid([vuln_items[:4], vuln_items[4:]]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"<b>{len(all_vulns)}</b> total vulnerabilities identified across all scans. "
        f"Of <b>{len(tickets)}</b> tracked tickets, <b>{len(patched)}</b> patched, "
        f"<b>{len(open_tickets)}</b> open, <b>{len(overdue)}</b> past SLA deadline.",
        S["body"]))
    story.append(Spacer(1, 16))

    # ── 3. Compliance ─────────────────────────────────────────────────────────
    story.append(_anchor("sec_compliance"))
    story.append(Paragraph("3. Compliance Standing", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    if fw_scores:
        if overall_compliance is not None:
            oc = GREEN if overall_compliance >= 70 else YELLOW if overall_compliance >= 40 else SEV_COLOR["critical"]
            hex_oc = "#" + oc.hexval()[2:]
            story.append(Paragraph(
                f'Overall Compliance Score: <font color="{hex_oc}"><b>{overall_compliance}%</b></font>',
                S["h3"]))
            story.append(Spacer(1, 6))
        fw_rows = [["Framework", "Score", "Compliant", "Applicable", "Status"]]
        for name, score, compliant, applicable in fw_scores:
            sc  = GREEN if score >= 70 else YELLOW if score >= 40 else SEV_COLOR["critical"]
            hex_sc = "#" + sc.hexval()[2:]
            status = "On Track" if score >= 70 else "Needs Work" if score >= 40 else "At Risk"
            fw_rows.append([
                name[:40],
                Paragraph(f'<font color="{hex_sc}"><b>{score}%</b></font>',
                          ParagraphStyle("fws", fontSize=9, alignment=TA_CENTER)),
                str(compliant), str(applicable), status,
            ])
        fwt = Table(fw_rows, colWidths=[2.4*inch, 0.8*inch, 0.9*inch, 1.1*inch, 1.3*inch])
        fwt.setStyle(_std_table_style())
        story.append(fwt)
    else:
        story.append(Paragraph(
            "No compliance frameworks configured. Navigate to GRC → Compliance.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 4. Risk Register ──────────────────────────────────────────────────────
    story.append(_anchor("sec_risk"))
    story.append(Paragraph("4. Risk Register Summary", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    risk_items = [
        ("CRITICAL RISKS", str(risk_lvl_cnt["critical"]), SEV_COLOR["critical"]),
        ("HIGH RISKS",     str(risk_lvl_cnt["high"]),     SEV_COLOR["high"]),
        ("MEDIUM RISKS",   str(risk_lvl_cnt["medium"]),   SEV_COLOR["medium"]),
        ("TOTAL OPEN",     str(len(open_risks)),          SLATE),
    ]
    story.append(_stat_grid([risk_items]))
    story.append(Spacer(1, 10))
    if open_risks:
        top_risks = sorted(open_risks, key=lambda r: -r.risk_score)[:8]
        risk_rows = [["Risk", "Category", "Score", "Level", "Status"]]
        for r in top_risks:
            risk_rows.append([
                r.title[:45],
                r.category.replace("_", " ").title(),
                str(r.risk_score),
                _sev_para(r.risk_level),
                r.status.replace("_", " ").title(),
            ])
        rrt = Table(risk_rows, colWidths=[2.2*inch, 1.1*inch, 0.6*inch, 0.8*inch, 1.2*inch])
        rrt.setStyle(_std_table_style())
        story.append(rrt)
    else:
        story.append(Paragraph("No open risks in the risk register.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 5. Remediation ────────────────────────────────────────────────────────
    story.append(_anchor("sec_remediation"))
    story.append(Paragraph("5. Remediation & SLA Performance", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    if tickets:
        rem_items = [
            ("OVERDUE",  str(sla_stat_cnt.get("overdue", 0)),  SEV_COLOR["critical"]),
            ("DUE SOON", str(sla_stat_cnt.get("due_soon", 0)), SEV_COLOR["medium"]),
            ("ON TRACK", str(sla_stat_cnt.get("on_track", 0)), GREEN),
            ("RESOLVED", str(sla_stat_cnt.get("resolved", 0)), BRAND),
        ]
        story.append(_stat_grid([rem_items]))
        story.append(Spacer(1, 10))
        rr = round(len(patched) / len(tickets) * 100) if tickets else 0
        story.append(Paragraph(
            f"Remediation rate: <b>{rr}%</b> of tracked vulnerabilities patched. "
            f"<b>{sla_stat_cnt.get('overdue', 0)}</b> findings exceeded SLA. "
            "SLA compliance is critical for audit readiness.", S["body"]))
    else:
        story.append(Paragraph("No vulnerability tickets tracked yet.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 6. Governance ─────────────────────────────────────────────────────────
    story.append(_anchor("sec_governance"))
    story.append(Paragraph("6. Policy & Governance Status", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    gov_items = [
        ("ACTIVE POLICIES", str(len(active_policies)), GREEN),
        ("DRAFT",           str(len(draft_policies)),  SEV_COLOR["medium"]),
        ("TOTAL",           str(len(policies)),         BRAND),
    ]
    story.append(_stat_grid([gov_items]))
    story.append(Spacer(1, 10))
    if policies:
        pol_rows = [["Policy", "Category", "Version", "Status"]]
        for p in sorted(policies, key=lambda x: (x.status != "active", x.title)):
            st_col = (GREEN if p.status == "active" else
                      SEV_COLOR["medium"] if p.status in ("draft", "under_review") else SLATE)
            pol_rows.append([
                p.title[:45],
                p.category.replace("_", " ").title(),
                p.version or "1.0",
                Paragraph(
                    f'<font color="{"#" + st_col.hexval()[2:]}">'
                    f'<b>{p.status.replace("_"," ").upper()}</b></font>',
                    ParagraphStyle("ps", fontSize=8, alignment=TA_CENTER)),
            ])
        pt = Table(pol_rows, colWidths=[2.8*inch, 1.4*inch, 0.7*inch, 1.1*inch])
        pt.setStyle(_std_table_style())
        story.append(pt)
    else:
        story.append(Paragraph("No policies defined. Navigate to GRC → Policies.", S["body"]))
    story.append(Spacer(1, 16))

    # ── 7. Audit Readiness ────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(_anchor("sec_audit"))
    story.append(Paragraph("7. Audit Readiness Assessment", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6))
    audit_checks = [
        ("Vulnerability Scanning Program Active",    len(completed_scans) > 0),
        ("Compliance Frameworks Configured",         len(frameworks) > 0),
        ("Risk Register Maintained",                 len(all_risks) > 0),
        ("Security Policies Active",                 len(active_policies) > 0),
        ("Vulnerability Tickets Tracked",            len(tickets) > 0),
        ("No Critical SLA Overdue",                  sla_stat_cnt.get("overdue", 0) == 0),
        ("Compliance Score ≥ 70%",               overall_compliance is not None and overall_compliance >= 70),
        ("No Open Critical Risks",                   len(critical_risks) == 0),
    ]
    passed = sum(1 for _, v in audit_checks if v)
    readiness = round(passed / len(audit_checks) * 100)
    r_col = GREEN if readiness >= 80 else YELLOW if readiness >= 60 else SEV_COLOR["critical"]
    hex_rc = "#" + r_col.hexval()[2:]
    story.append(Paragraph(
        f'Audit Readiness: <font color="{hex_rc}"><b>{readiness}%</b></font>'
        f"  ({passed}/{len(audit_checks)} checks passing)", S["h3"]))
    story.append(Spacer(1, 8))
    audit_rows = [["Audit Check", "Status"]]
    for check, ok in audit_checks:
        sc = GREEN if ok else SEV_COLOR["critical"]
        hex_sc = "#" + sc.hexval()[2:]
        audit_rows.append([
            check,
            Paragraph(f'<font color="{hex_sc}"><b>{"PASS" if ok else "FAIL"}</b></font>',
                      ParagraphStyle("aus", fontSize=9, alignment=TA_CENTER)),
        ])
    at = Table(audit_rows, colWidths=[4.5*inch, 2*inch])
    at.setStyle(_std_table_style())
    story.append(at)
    story.append(Spacer(1, 16))

    # ── 8. Executive Recommendations ─────────────────────────────────────────
    story.append(_anchor("sec_exec_rec"))
    story.append(Paragraph("8. Executive Recommendations", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8))

    exec_recs = []
    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        exec_recs.append(("PRIORITY 1", SEV_COLOR["critical"],
            f"Authorize emergency patching for {sev_counts['critical']} Critical and "
            f"{sev_counts['high']} High findings. Allocate engineering resources immediately."))
    if sla_stat_cnt.get("overdue", 0) > 0:
        exec_recs.append(("PRIORITY 2", SEV_COLOR["high"],
            f"Review {sla_stat_cnt.get('overdue',0)} SLA-overdue vulnerabilities with asset owners. "
            "Establish accepted-risk documentation or emergency patches within 5 business days."))
    if overall_compliance is not None and overall_compliance < 70:
        exec_recs.append(("COMPLIANCE", YELLOW,
            f"Compliance score of {overall_compliance}% is below the 70% threshold. "
            "Schedule remediation workshops and assign owners to failing controls."))
    if len(critical_risks) > 0:
        exec_recs.append(("RISK", SEV_COLOR["critical"],
            f"{len(critical_risks)} critical risks remain open. "
            "Escalate to the Board Risk Committee and establish formal mitigation timelines."))
    if len(draft_policies) > 0:
        exec_recs.append(("GOVERNANCE", BRAND,
            f"{len(draft_policies)} policies remain in draft. "
            "Complete review and approval to strengthen governance posture and audit readiness."))
    exec_recs.append(("PROGRAM", GREEN,
        "Maintain monthly executive security briefings, quarterly compliance reviews, "
        "and annual penetration testing to sustain security program maturity."))

    for priority, col, text in exec_recs:
        hex_c = "#" + col.hexval()[2:]
        block = KeepTogether([
            Table([[
                Paragraph(f'<font color="{hex_c}"><b>{priority}</b></font>',
                          ParagraphStyle("erp", fontSize=8, alignment=TA_CENTER)),
                Paragraph(text, S["body"]),
            ]], colWidths=[0.9*inch, 5.6*inch],
               style=TableStyle([
                   ("BACKGROUND", (0, 0), (-1, -1), LGRAY),
                   ("VALIGN", (0, 0), (-1, -1), "TOP"),
                   ("TOPPADDING", (0, 0), (-1, -1), 7),
                   ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                   ("LEFTPADDING", (0, 0), (-1, -1), 8),
                   ("LINEABOVE", (0, 0), (-1, 0), 0.5, BORDER),
               ])),
        ])
        story.append(block)
        story.append(Spacer(1, 4))

    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    return buf.getvalue()
