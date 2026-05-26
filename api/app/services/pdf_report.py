"""Generate a PDF compliance summary report using fpdf2."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fpdf import FPDF

from app.models.aws_account import AwsAccount

_REPLACEMENTS = {
    "—": "-",   # em dash
    "–": "-",   # en dash
    "…": "...", # ellipsis
    "·": ".",   # middle dot
    "’": "'",   # right single quote
    "‘": "'",   # left single quote
    "“": '"',   # left double quote
    "”": '"',   # right double quote
}

def _s(text: str) -> str:
    """Sanitize string to Latin-1 safe for Helvetica."""
    for ch, rep in _REPLACEMENTS.items():
        text = text.replace(ch, rep)
    return text.encode("latin-1", errors="replace").decode("latin-1")

_STATUS_COLOR = {
    "pass": (22, 163, 74),    # green-600
    "fail": (220, 38, 38),    # red-600
    "partial": (217, 119, 6), # amber-600
    "no_data": (113, 113, 122), # zinc-500
}

_FRAMEWORK_LABELS = {
    "soc2": "SOC 2 Trust Services Criteria",
    "cis_aws_l1": "CIS Amazon Web Services Foundations Benchmark - Level 1",
    "iso27001": "ISO 27001:2022 Annex A",
}


def build_pdf(
    acc: AwsAccount,
    framework: str,
    period_days: int,
    generated_at: datetime,
    control_results: list[dict[str, Any]],
) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(24, 24, 27)
    pdf.cell(0, 10, "Vigil - Compliance Evidence Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(82, 82, 91)
    fw_label = _s(_FRAMEWORK_LABELS.get(framework, framework.upper()))
    pdf.cell(pdf.epw, 7, fw_label, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Meta table
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(63, 63, 70)
    meta = [
        ("Account", f"{_s(acc.label)}  ({acc.account_id or 'unknown'})"),
        ("Period", f"Last {period_days} days"),
        ("Generated", generated_at.strftime("%Y-%m-%d %H:%M UTC")),
    ]
    for label, value in meta:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(28, 6, label + ":", new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, value, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Score summary bar
    passed = sum(1 for r in control_results if r["status"] == "pass")
    failed = sum(1 for r in control_results if r["status"] == "fail")
    no_data = sum(1 for r in control_results if r["status"] == "no_data")
    total = len(control_results)
    score_pct = round((passed / total) * 100) if total else 0

    box_h = 14
    rect_y = pdf.get_y()
    pdf.set_fill_color(244, 244, 245)
    pdf.set_draw_color(228, 228, 231)
    pdf.rect(pdf.l_margin, rect_y, pdf.epw, box_h, style="FD")

    text_y = rect_y + (box_h - 6) / 2
    pdf.set_xy(pdf.l_margin + 4, text_y)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(24, 24, 27)
    pdf.cell(26, 6, f"{score_pct}%")

    pdf.set_xy(pdf.l_margin + 32, text_y)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(82, 82, 91)
    pdf.cell(pdf.epw - 32, 6, f"pass rate - {passed} pass  |  {failed} fail  |  {no_data} no data  |  {total} total")

    pdf.set_y(rect_y + box_h + 6)

    # Control table header
    pdf.set_fill_color(39, 39, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    col_w = [22, 110, 22, 26]
    headers = ["Control", "Title", "Status", "Findings"]
    for i, h in enumerate(headers):
        pdf.cell(col_w[i], 7, h, border=0, fill=True, align="C" if i > 1 else "L")
    pdf.ln()

    # Control rows
    pdf.set_font("Helvetica", "", 9)
    for idx, r in enumerate(control_results):
        fill = idx % 2 == 0
        bg = (249, 250, 251) if fill else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_text_color(24, 24, 27)

        pdf.cell(col_w[0], 6, _s(r["control_id"]), border=0, fill=fill)
        title = _s(r["title"])
        title = title[:62] + "..." if len(title) > 62 else title
        pdf.cell(col_w[1], 6, title, border=0, fill=fill)

        status = r["status"]
        color = _STATUS_COLOR.get(status, _STATUS_COLOR["no_data"])
        pdf.set_text_color(*color)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(col_w[2], 6, status.upper(), border=0, fill=fill, align="C")
        pdf.set_text_color(24, 24, 27)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(col_w[3], 6, str(r["finding_count"]), border=0, fill=fill, align="C")
        pdf.ln()

    pdf.ln(6)

    # Failed controls detail
    failed_controls = [r for r in control_results if r["status"] == "fail"]
    if failed_controls:
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(24, 24, 27)
        pdf.cell(0, 8, "Failed Controls - Detail", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

        for r in failed_controls:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(220, 38, 38)
            ctrl_title = _s(f"{r['control_id']}  -  {r['title']}")[:100]
            pdf.cell(pdf.epw, 6, ctrl_title, new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(82, 82, 91)
            pdf.multi_cell(pdf.epw, 5, _s(r["description"][:300]))
            if r.get("guidance"):
                pdf.set_x(pdf.l_margin)
                pdf.set_font("Helvetica", "I", 9)
                pdf.multi_cell(pdf.epw, 5, _s("Guidance: " + r["guidance"][:200]))

            if r["findings"]:
                pdf.set_x(pdf.l_margin)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(24, 24, 27)
                pdf.cell(pdf.epw, 5, f"  Open findings ({len(r['findings'])}):", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(63, 63, 70)
                for f in r["findings"][:5]:
                    arn = f["resource_arn"]
                    arn_short = arn[:65] + "..." if len(arn) > 65 else arn
                    line = _s(f"[{f['severity'].upper()}] {f['title']} - {arn_short}")
                    pdf.set_x(pdf.l_margin + 4)
                    pdf.multi_cell(pdf.epw - 4, 4.5, line, new_x="LMARGIN", new_y="NEXT")
                if len(r["findings"]) > 5:
                    pdf.set_x(pdf.l_margin + 4)
                    pdf.cell(pdf.epw - 4, 4.5, f"... and {len(r['findings']) - 5} more (see findings.json)", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(pdf.l_margin)
            pdf.ln(4)

    # Footer
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(161, 161, 170)
    pdf.cell(0, 5, f"Generated by Vigil  |  {generated_at.strftime('%Y-%m-%d %H:%M UTC')}  |  Read-only AWS evidence - not a guarantee of compliance.", align="C")

    return bytes(pdf.output())
