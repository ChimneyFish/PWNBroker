"""
Generate a professional compliance audit report PDF using ReportLab.
"""
import io
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

# ── Palette ────────────────────────────────────────────────────────────────────
CYAN   = colors.HexColor("#0891b2")
DARK   = colors.HexColor("#0f172a")
SLATE  = colors.HexColor("#475569")
LGRAY  = colors.HexColor("#f1f5f9")
BORDER = colors.HexColor("#cbd5e1")
GREEN  = colors.HexColor("#15803d")
YELLOW = colors.HexColor("#b45309")
RED    = colors.HexColor("#dc2626")
MUTED  = colors.HexColor("#94a3b8")
WHITE  = colors.white
BLACK  = colors.HexColor("#0f172a")

STATUS_MAP = {
    "compliant":      ("Compliant",     GREEN),
    "partial":        ("Partial",       YELLOW),
    "non_compliant":  ("Non-Compliant", RED),
    "not_applicable": ("N/A",           MUTED),
    "not_assessed":   ("Not Assessed",  SLATE),
}


def _hex(color):
    """Convert a ReportLab Color to '#rrggbb' string for XML tags."""
    h = color.hexval()  # returns '0xrrggbb'
    return "#" + h[2:]


def _fmt_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _styles():
    base = getSampleStyleSheet()
    return {
        "cover_sub": ParagraphStyle("cover_sub", fontSize=9, textColor=SLATE,
                                    fontName="Helvetica", spaceAfter=2),
        "cover_h1":  ParagraphStyle("cover_h1",  fontSize=26, textColor=DARK,
                                    fontName="Helvetica-Bold", spaceAfter=4, leading=30),
        "cover_ver": ParagraphStyle("cover_ver", fontSize=10, textColor=SLATE,
                                    fontName="Helvetica", spaceAfter=6),
        "h2":        ParagraphStyle("h2", fontSize=13, textColor=CYAN,
                                    fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "h3":        ParagraphStyle("h3", fontSize=10, textColor=DARK,
                                    fontName="Helvetica-Bold", spaceBefore=6, spaceAfter=2),
        "body":      ParagraphStyle("body", fontSize=8.5, textColor=BLACK,
                                    fontName="Helvetica", leading=13),
        "small":     ParagraphStyle("small", fontSize=7.5, textColor=SLATE,
                                    fontName="Helvetica", leading=11),
        "ev":        ParagraphStyle("ev", fontSize=7.5, textColor=SLATE,
                                    fontName="Helvetica-Oblique", leading=11),
    }


def _page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE)
    canvas.drawString(25 * mm, 12 * mm, "PwnBroker — Compliance Audit Report — CONFIDENTIAL")
    canvas.drawRightString(A4[0] - 25 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_compliance_pdf(fw, by_cat, evidence_by_control=None):
    """
    fw              : ComplianceFramework ORM object
    by_cat          : dict[category_str, list[ComplianceControl]]
    evidence_by_control : dict[control_id, list[EvidenceFile]] or None
    Returns bytes of the PDF.
    """
    evidence_by_control = evidence_by_control or {}
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=25 * mm, rightMargin=25 * mm,
        topMargin=22 * mm, bottomMargin=22 * mm,
    )
    S = _styles()
    story = []

    # ── Tally ────────────────────────────────────────────────────────────────
    all_controls = [c for cats in by_cat.values() for c in cats]
    tally = {k: 0 for k in STATUS_MAP}
    for c in all_controls:
        s = c.assessment.status if c.assessment else "not_assessed"
        tally[s] = tally.get(s, 0) + 1
    total = len(all_controls)
    na    = tally["not_applicable"]
    score = round(tally["compliant"] / max(total - na, 1) * 100)
    score_color = GREEN if score >= 70 else (YELLOW if score >= 40 else RED)

    # ── Cover Page ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 35 * mm))

    # Cyan accent bar
    bar = Table([[""]],
                colWidths=[4 * mm], rowHeights=[20 * mm])
    bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CYAN),
                              ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    header_content = Table([[bar, [
        Paragraph("COMPLIANCE AUDIT REPORT", S["cover_sub"]),
        Paragraph(fw.name, S["cover_h1"]),
        Paragraph(f"Version {fw.version}" if fw.version else "", S["cover_ver"]),
    ]]], colWidths=[8 * mm, None])
    header_content.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("LEFTPADDING", (1, 0), (1, -1), 6),
    ]))
    story.append(header_content)
    story.append(Spacer(1, 8 * mm))

    if fw.description:
        story.append(Paragraph(fw.description, S["body"]))
        story.append(Spacer(1, 4 * mm))

    now = datetime.now(timezone.utc)
    story.append(Paragraph(
        f"Report generated: {now.strftime('%d %B %Y at %H:%M UTC')}", S["body"]))
    story.append(Paragraph("Platform: PwnBroker Security Management", S["small"]))
    story.append(Spacer(1, 10 * mm))

    # Score banner
    score_tbl = Table(
        [["Overall Compliance Score", f"{score}%"]],
        colWidths=[120 * mm, None],
    )
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, 0), LGRAY),
        ("BACKGROUND",   (1, 0), (1, 0), LGRAY),
        ("TEXTCOLOR",    (0, 0), (0, 0), DARK),
        ("TEXTCOLOR",    (1, 0), (1, 0), score_color),
        ("FONTNAME",     (0, 0), (0, 0), "Helvetica"),
        ("FONTNAME",     (1, 0), (1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 12),
        ("ALIGN",        (1, 0), (1, 0), "RIGHT"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 4 * mm),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4 * mm),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("BOX",          (0, 0), (-1, -1), 1, BORDER),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 6 * mm))

    # Status summary row
    sum_data = [
        ["Compliant", "Partial", "Non-Compliant", "N/A", "Not Assessed"],
        [str(tally["compliant"]), str(tally["partial"]),
         str(tally["non_compliant"]), str(tally["not_applicable"]),
         str(tally["not_assessed"])],
    ]
    sum_tbl = Table(sum_data, colWidths=[32 * mm] * 5)
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 1), (-1, 1), 12),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
        ("GRID",          (0, 0), (-1, -1), 0.5, BORDER),
        ("TEXTCOLOR", (0, 1), (0, 1), GREEN),
        ("TEXTCOLOR", (1, 1), (1, 1), YELLOW),
        ("TEXTCOLOR", (2, 1), (2, 1), RED),
    ]))
    story.append(sum_tbl)
    story.append(PageBreak())

    # ── Category Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Category Summary", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=4))

    cat_rows = [["Category", "Total", "✓", "~", "✗", "N/A", "Score"]]
    for cat, controls in by_cat.items():
        cc = {k: 0 for k in STATUS_MAP}
        for c in controls:
            s = c.assessment.status if c.assessment else "not_assessed"
            cc[s] = cc.get(s, 0) + 1
        n = len(controls)
        p = round(cc["compliant"] / max(n - cc["not_applicable"], 1) * 100)
        cat_rows.append([cat, str(n), str(cc["compliant"]), str(cc["partial"]),
                         str(cc["non_compliant"]), str(cc["not_applicable"]), f"{p}%"])

    ct = Table(cat_rows, colWidths=[62 * mm, 16 * mm, 14 * mm, 14 * mm, 22 * mm, 14 * mm, 18 * mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LGRAY]),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2.5 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5 * mm),
        ("GRID",          (0, 0), (-1, -1), 0.3, BORDER),
        ("LINEBELOW",     (0, 0), (-1, 0), 1, SLATE),
    ]))
    story.append(ct)
    story.append(PageBreak())

    # ── Control Details ───────────────────────────────────────────────────────
    story.append(Paragraph("Control Assessment Details", S["h2"]))

    for cat, controls in by_cat.items():
        story.append(Paragraph(cat, S["h3"]))
        story.append(HRFlowable(width="100%", thickness=0.3, color=BORDER, spaceAfter=2))

        for ctrl in controls:
            a = ctrl.assessment
            status_key   = a.status if a else "not_assessed"
            status_label, status_color = STATUS_MAP.get(status_key, ("?", SLATE))
            notes  = (a.notes or "").strip() if a else ""
            ev_files = evidence_by_control.get(ctrl.id, [])

            ctrl_block = []

            # Header row: control ID + title + status badge
            hdr = Table([[
                Paragraph(f'<font color="#475569"><b>{ctrl.control_id}</b></font>', S["body"]),
                Paragraph(f'<b>{ctrl.title}</b>', S["body"]),
                Paragraph(f'<b><font color="{_hex(status_color)}">{status_label}</font></b>', S["body"]),
            ]], colWidths=[22 * mm, 105 * mm, 33 * mm])
            hdr.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), LGRAY),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 2 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
                ("LEFTPADDING",   (0, 0), (-1, -1), 3 * mm),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 2 * mm),
                ("LINEABOVE",     (0, 0), (-1, 0), 0.5, BORDER),
            ]))
            ctrl_block.append(hdr)

            # Description row (if present)
            if ctrl.description:
                desc_tbl = Table([[Paragraph(ctrl.description, S["small"])]],
                                  colWidths=[160 * mm])
                desc_tbl.setStyle(TableStyle([
                    ("LEFTPADDING",   (0, 0), (-1, -1), 25 * mm),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 3 * mm),
                    ("TOPPADDING",    (0, 0), (-1, -1), 1 * mm),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1 * mm),
                ]))
                ctrl_block.append(desc_tbl)

            # Notes + assessor row
            if notes or (a and a.assessed_at):
                assessor_str = ""
                if a and a.assessed_at:
                    assessor_str = a.assessed_at.strftime("%Y-%m-%d")
                    if a.assessor:
                        assessor_str += f" by {a.assessor.username}"
                detail_tbl = Table([[
                    Paragraph(f"<i>Notes:</i> {notes}" if notes else "", S["small"]),
                    Paragraph(assessor_str, S["small"]),
                ]], colWidths=[120 * mm, 40 * mm])
                detail_tbl.setStyle(TableStyle([
                    ("LEFTPADDING",   (0, 0), (-1, -1), 25 * mm),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 3 * mm),
                    ("TOPPADDING",    (0, 0), (-1, -1), 1 * mm),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
                    ("ALIGN",         (1, 0), (1, 0), "RIGHT"),
                ]))
                ctrl_block.append(detail_tbl)

            # Evidence files
            if ev_files:
                for ef in ev_files:
                    size_str = _fmt_size(ef.file_size)
                    date_str = ef.uploaded_at.strftime("%Y-%m-%d")
                    desc_str = f" — {ef.description}" if ef.description else ""
                    ev_tbl = Table([[
                        Paragraph(f"📎 {ef.filename}  ({size_str}, {date_str}){desc_str}", S["ev"]),
                    ]], colWidths=[160 * mm])
                    ev_tbl.setStyle(TableStyle([
                        ("LEFTPADDING",   (0, 0), (-1, -1), 28 * mm),
                        ("TOPPADDING",    (0, 0), (-1, -1), 0.5 * mm),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5 * mm),
                    ]))
                    ctrl_block.append(ev_tbl)

            story.append(KeepTogether(ctrl_block))

        story.append(Spacer(1, 4 * mm))

    # ── Evidence Index ────────────────────────────────────────────────────────
    all_ev = [ef for ev_list in evidence_by_control.values() for ef in ev_list]
    if all_ev:
        story.append(PageBreak())
        story.append(Paragraph("Evidence Index", S["h2"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=4))

        ev_rows = [["File", "Control", "Size", "Uploaded", "Description"]]
        for ef in sorted(all_ev, key=lambda e: e.filename.lower()):
            ctrl_ref = ef.control.control_id if ef.control else "—"
            ev_rows.append([
                ef.filename,
                ctrl_ref,
                _fmt_size(ef.file_size),
                ef.uploaded_at.strftime("%Y-%m-%d"),
                ef.description or "",
            ])
        ev_tbl = Table(ev_rows, colWidths=[50 * mm, 22 * mm, 16 * mm, 22 * mm, 50 * mm])
        ev_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LGRAY]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 2 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
            ("LEFTPADDING",   (0, 0), (-1, -1), 2 * mm),
            ("GRID",          (0, 0), (-1, -1), 0.3, BORDER),
            ("LINEBELOW",     (0, 0), (-1, 0), 1, SLATE),
            ("WORDWRAP",      (0, 0), (-1, -1), 1),
        ]))
        story.append(ev_tbl)

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return buf.getvalue()
