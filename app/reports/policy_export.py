"""
Render a Policy's content into a downloadable PDF using ReportLab, mirroring
the visual language of the compliance audit report. The policy body is plain
text with a small set of line-based conventions ("# " / "## " headings,
"- " bullets, "| ... |" tables) which are parsed into flowables.
"""
import io
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

CYAN   = colors.HexColor("#0891b2")
DARK   = colors.HexColor("#0f172a")
SLATE  = colors.HexColor("#475569")
LGRAY  = colors.HexColor("#f1f5f9")
BORDER = colors.HexColor("#cbd5e1")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("p_title", fontSize=22, textColor=DARK,
                                 fontName="Helvetica-Bold", spaceAfter=4, leading=26),
        "meta":  ParagraphStyle("p_meta", fontSize=9, textColor=SLATE,
                                 fontName="Helvetica", spaceAfter=2),
        "h1":    ParagraphStyle("p_h1", fontSize=14, textColor=DARK,
                                 fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "h2":    ParagraphStyle("p_h2", fontSize=11.5, textColor=CYAN,
                                 fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3),
        "body":  ParagraphStyle("p_body", fontSize=9.5, textColor=DARK,
                                 fontName="Helvetica", leading=14, spaceAfter=4),
        "bullet": ParagraphStyle("p_bullet", fontSize=9.5, textColor=DARK,
                                  fontName="Helvetica", leading=13),
        "cell":  ParagraphStyle("p_cell", fontSize=8.5, textColor=DARK,
                                 fontName="Helvetica", leading=11),
    }


def _page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE)
    canvas.drawString(25 * mm, 12 * mm, "PwnBroker — Policy Document — CONFIDENTIAL")
    canvas.drawRightString(A4[0] - 25 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _parse_body(lines, S):
    """Turn plain-text policy body lines into a list of flowables."""
    flow = []
    bullets = []
    table_rows = []

    def flush_bullets():
        nonlocal bullets
        if bullets:
            flow.append(ListFlowable(
                [ListItem(Paragraph(b, S["bullet"]), leftIndent=4) for b in bullets],
                bulletType="bullet", start="•", leftIndent=10, spaceBefore=2, spaceAfter=6,
            ))
            bullets = []

    def flush_table():
        nonlocal table_rows
        if table_rows:
            data = [[Paragraph(cell.strip(), S["cell"]) for cell in row] for row in table_rows]
            ncols = max(len(r) for r in data)
            colw = (A4[0] - 50 * mm) / ncols
            tbl = Table(data, colWidths=[colw] * ncols)
            tbl.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("BACKGROUND", (0, 0), (-1, 0), LGRAY),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            flow.append(tbl)
            flow.append(Spacer(1, 4 * mm))
            table_rows = []

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        if not stripped:
            flush_bullets()
            flush_table()
            continue

        if stripped.startswith("| "):
            flush_bullets()
            if set(stripped.replace("|", "").strip()) <= {"-", " ", ":"}:
                continue  # markdown separator row
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            table_rows.append(cells)
            continue
        else:
            flush_table()

        if stripped.startswith("# "):
            flush_bullets()
            flow.append(Paragraph(stripped[2:].strip(), S["h1"]))
            flow.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=4))
        elif stripped.startswith("## "):
            flush_bullets()
            flow.append(Paragraph(stripped[3:].strip(), S["h2"]))
        elif stripped.startswith("- "):
            bullets.append(_inline(stripped[2:].strip()))
        else:
            flush_bullets()
            flow.append(Paragraph(_inline(stripped), S["body"]))

    flush_bullets()
    flush_table()
    return flow


def _inline(text):
    """Minimal bold markdown (**text**) -> ReportLab <b> tag; escape XML first."""
    text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)


def generate_policy_pdf(policy):
    """policy: Policy ORM object. Returns PDF bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=25 * mm, rightMargin=25 * mm,
        topMargin=22 * mm, bottomMargin=22 * mm,
    )
    S = _styles()
    story = []

    story.append(Paragraph(policy.title, S["title"]))
    story.append(Paragraph(
        f"Category: {(policy.category or 'general').replace('_',' ').title()}  ·  "
        f"Version {policy.version or '1.0'}  ·  Status: {(policy.status or 'draft').replace('_',' ').title()}",
        S["meta"]))
    if policy.owner:
        story.append(Paragraph(f"Owner: {policy.owner.username}", S["meta"]))
    if policy.review_date:
        story.append(Paragraph(f"Next Review: {policy.review_date.strftime('%Y-%m-%d')}", S["meta"]))
    now = datetime.now(timezone.utc)
    story.append(Paragraph(f"Exported: {now.strftime('%d %B %Y at %H:%M UTC')}", S["meta"]))
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=6))

    body = policy.content or policy.description or "No content has been added to this policy yet."
    story.extend(_parse_body(body.splitlines(), S))

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return buf.getvalue()
