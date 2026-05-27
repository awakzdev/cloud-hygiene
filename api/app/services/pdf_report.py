"""Generate an auditor-ready PDF compliance evidence report using fpdf2."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fpdf import FPDF

from app.models.aws_account import AwsAccount

_REPLACEMENTS = {
    "—": "-",
    "–": "-",
    "…": "...",
    "·": ".",
    "\u2019": "'",
    "\u2018": "'",
    "\u201c": '"',
    "\u201d": '"',
}

# Print-oriented type scale (pt) — nothing below 8pt
_FONT = {
    "h1": 27,
    "h2": 16,
    "h3": 12.5,
    "body": 10.5,
    "table": 10,
    "finding": 10.5,
    "finding_meta": 9.5,
    "finding_title": 11,
    "label": 9,
    "footer": 8,
    "badge": 8.5,
    "muted": 9,
    "meta": 8.5,
}

# Finding row layout — 72px badge column, ~14px gap at print scale
_FINDING_BADGE_COL = 19
_FINDING_CONTENT_GAP = 3.5
_FINDING_ROW_PAD = 4
_FINDING_ROW_GAP = 3
_FINDING_LINE_H = 5.5

# Card / table layout
_CARD_INNER_RPAD = 4
_CARD_BOTTOM_PAD = 4.5
_CARD_GAP = 4
_TABLE_ROW_COMPACT = 8
_TABLE_HEADER_H = 11
_PAGE_BOTTOM = 22

# Resource line colors (~#4b5563 / #374151)
_RESOURCE_LABEL_COLOR = (75, 85, 99)
_RESOURCE_VALUE_COLOR = (55, 65, 81)

_ALIGN = "L"


def _page_bottom(pdf: FPDF) -> float:
    return pdf.h - pdf.b_margin


def _vigil_mark_path() -> Path | None:
    """Bundled favicon mark for PDF header; falls back to web asset in dev."""
    candidates = [
        Path(__file__).resolve().parent.parent / "assets" / "vigil-mark.png",
        Path(__file__).resolve().parents[3] / "web" / "public" / "favicon.png",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def _draw_report_header(pdf: FPDF, pack_badge: str, framework_label: str) -> None:
    """Branded top row: logo + wordmark left, evidence pack badge right, then title block."""
    header_y = pdf.get_y()
    mark_path = _vigil_mark_path()
    wordmark_color = (17, 24, 39)

    mark_y = header_y + (_BRAND_ROW_H - _LOGO_SIZE_MM) / 2
    text_y = header_y + (_BRAND_ROW_H - _WORDMARK_CELL_H) / 2

    if mark_path is not None:
        pdf.image(str(mark_path), x=pdf.l_margin, y=mark_y, w=_LOGO_SIZE_MM)
        text_x = pdf.l_margin + _LOGO_SIZE_MM + _LOGO_GAP_MM
    else:
        text_x = pdf.l_margin

    pdf.set_xy(text_x, text_y)
    pdf.set_font("Helvetica", "B", _WORDMARK_PT)
    pdf.set_text_color(*wordmark_color)
    pdf.cell(36, _WORDMARK_CELL_H, "Vigil")

    badge_subtitle = "Read-only source evidence"
    pdf.set_font("Helvetica", "B", _FONT["badge"])
    title_w = pdf.get_string_width(_s(pack_badge))
    pdf.set_font("Helvetica", "", _FONT["footer"])
    sub_w = pdf.get_string_width(_s(badge_subtitle))
    badge_w = max(title_w, sub_w) + _BADGE_PAD_X * 2
    badge_h = _BADGE_PAD_Y * 2 + 4.5 + 3.5

    badge_x = pdf.w - pdf.r_margin - badge_w
    badge_y = header_y - 0.5
    pdf.set_xy(badge_x, badge_y)
    pdf.set_fill_color(238, 242, 255)
    pdf.set_draw_color(199, 210, 254)
    pdf.set_line_width(0.2)
    pdf.rect(badge_x, badge_y, badge_w, badge_h, style="FD")

    pdf.set_xy(badge_x + _BADGE_PAD_X, badge_y + _BADGE_PAD_Y)
    pdf.set_font("Helvetica", "B", _FONT["badge"])
    pdf.set_text_color(67, 56, 202)
    pdf.cell(badge_w - _BADGE_PAD_X * 2, 4.5, _s(pack_badge))

    pdf.set_xy(badge_x + _BADGE_PAD_X, badge_y + _BADGE_PAD_Y + 5)
    pdf.set_font("Helvetica", "", _FONT["footer"])
    pdf.set_text_color(99, 102, 241)
    pdf.cell(badge_w - _BADGE_PAD_X * 2, 3.5, _s(badge_subtitle))

    row_bottom = max(header_y + _BRAND_ROW_H, badge_y + badge_h)
    pdf.set_y(row_bottom + _BADGE_TITLE_GAP)

    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(24, 24, 27)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 9, "Compliance Evidence Report", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(_HEADER_SUBTITLE_GAP - 4)

    pdf.set_font("Helvetica", "", _FONT["body"])
    pdf.set_text_color(82, 82, 91)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 5, _s(framework_label), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(_HEADER_DIVIDER_GAP)

    pdf.set_draw_color(212, 212, 216)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(_HEADER_META_GAP)

_FRAMEWORK_LABELS = {
    "soc2": "SOC 2 Trust Services Criteria",
    "cis_aws_l1": "CIS Amazon Web Services Foundations Benchmark - Level 1",
    "iso27001": "ISO 27001:2022 Annex A",
}

_FRAMEWORK_SHORT = {
    "soc2": "SOC 2",
    "cis_aws_l1": "CIS AWS L1",
    "iso27001": "ISO 27001",
}

_FRAMEWORK_PACK_BADGE = {
    "soc2": "SOC 2 Evidence Pack",
    "cis_aws_l1": "CIS AWS Evidence Pack",
    "iso27001": "ISO 27001 Evidence Pack",
}

_CONTROL_STATUS = {
    "pass": {"label": "Pass", "fill": (236, 253, 245), "text": (22, 101, 52), "border": (167, 243, 208)},
    "fail": {"label": "Needs Review", "fill": (255, 251, 235), "text": (180, 83, 9), "border": (253, 230, 138)},
    "no_data": {"label": "No data", "fill": (250, 250, 250), "text": (113, 113, 122), "border": (228, 228, 231)},
}

_EVIDENCE_STATUS = {
    "complete": {"label": "Complete", "fill": (239, 246, 255), "text": (29, 78, 216), "border": (191, 219, 254)},
    "partial": {"label": "Partial", "fill": (255, 251, 235), "text": (180, 83, 9), "border": (253, 230, 138)},
    "missing": {"label": "Missing", "fill": (250, 250, 250), "text": (113, 113, 122), "border": (228, 228, 231)},
}

_SEVERITY_STYLE = {
    "critical": {"fill": (254, 226, 226), "text": (185, 28, 28), "border": (252, 165, 165)},
    "high": {"fill": (254, 226, 226), "text": (220, 38, 38), "border": (252, 165, 165)},
    "medium": {"fill": (254, 243, 199), "text": (180, 83, 9), "border": (253, 230, 138)},
    "low": {"fill": (244, 244, 245), "text": (113, 113, 122), "border": (212, 212, 216)},
}

_SUMMARY_ACCENTS = {
    "pass": (34, 197, 94),
    "review": (245, 158, 11),
    "neutral": (161, 161, 170),
}

_CARD_PAD = 7
_META_PAD = 4
_SECTION_GAP = 5

# Control overview table column fractions
_TABLE_COL_FR = [0.09, 0.36, 0.16, 0.22, 0.12]

_SEV_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_KEY_CONTROLS_LIMIT = 5

# Header branding (mm) — ~20px icon, ~20pt wordmark, aligned row
_LOGO_SIZE_MM = 7.2
_LOGO_GAP_MM = 2.8
_WORDMARK_PT = 20
_WORDMARK_CELL_H = 6.5
_BRAND_ROW_H = 8.5
_BADGE_TITLE_GAP = 8.0
_HEADER_SUBTITLE_GAP = 4.5
_HEADER_DIVIDER_GAP = 5.0
_HEADER_META_GAP = 6.0
_BADGE_PAD_X = 4.0
_BADGE_PAD_Y = 3.5


def _s(text: str) -> str:
    for ch, rep in _REPLACEMENTS.items():
        text = text.replace(ch, rep)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _truncate_middle(text: str, max_len: int = 72) -> str:
    if len(text) <= max_len:
        return text
    keep = (max_len - 3) // 2
    return text[:keep] + "..." + text[-keep:]


def _truncate_arn(arn: str, max_len: int = 72) -> str:
    """Friendly single-line resource display for PDFs; full values remain in JSON."""
    if not arn:
        return "-"

    if arn.startswith("arn:aws:s3:::"):
        display = arn.replace("arn:aws:s3:::", "s3://", 1)
        return display if len(display) <= max_len else _truncate_middle(display, max_len)

    if arn.startswith("arn:aws:iam::") and ":role/" in arn:
        account = arn.split("arn:aws:iam::", 1)[1].split(":", 1)[0]
        role_path = arn.split(":role/", 1)[1]
        role_name = role_path.rsplit("/", 1)[-1]
        display = f"aws:iam::{account}:role/{role_name}"
        return display if len(display) <= max_len else _truncate_middle(display, max_len)

    if arn.startswith("arn:aws:iam::") and ":user/" in arn:
        account = arn.split("arn:aws:iam::", 1)[1].split(":", 1)[0]
        user_name = arn.split(":user/", 1)[1].rsplit("/", 1)[-1]
        display = f"aws:iam::{account}:user/{user_name}"
        return display if len(display) <= max_len else _truncate_middle(display, max_len)

    if arn.startswith("github://"):
        return arn if len(arn) <= max_len else _truncate_middle(arn, max_len)

    if arn.startswith("gitlab://"):
        return arn if len(arn) <= max_len else _truncate_middle(arn, max_len)

    if len(arn) <= max_len:
        return arn
    return _truncate_middle(arn, max_len)


def _resource_line(pdf: FPDF, arn: str, max_w: float) -> tuple[str, str]:
    """Return (label, value) — single line, middle-truncated."""
    display = _truncate_arn(arn)
    label = "Resource: "
    pdf.set_font("Helvetica", "B", _FONT["finding_meta"])
    label_w = pdf.get_string_width(_s(label))
    value_w = max_w - label_w
    pdf.set_font("Helvetica", "", _FONT["finding_meta"])
    while len(display) > 16 and pdf.get_string_width(_s(display)) > value_w:
        display = _truncate_middle(display, max(16, len(display) - 8))
    return label, display


def _objective_text(title: str) -> str:
    t = _s(title)
    if " - " in t:
        t = t.split(" - ", 1)[-1].strip()
    elif "-" in t:
        parts = t.split("-", 1)
        if len(parts) > 1 and parts[1].strip():
            t = parts[1].strip()
    return t


def _short_objective(title: str, max_len: int = 48) -> str:
    t = _objective_text(title)
    return t[: max_len - 3] + "..." if len(t) > max_len else t


def _wrap_lines(pdf: FPDF, w: float, text: str, line_h: float) -> list[str]:
    return pdf.multi_cell(w, line_h, _s(text), dry_run=True, output="LINES", align=_ALIGN)


def _para(pdf: FPDF, w: float, text: str, line_h: float, font_size: float, style: str = "") -> None:
    """Left-aligned paragraph — never justified."""
    pdf.set_font("Helvetica", style, font_size)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(w, line_h, _s(text), align=_ALIGN)


def _block_height(pdf: FPDF, w: float, text: str, line_h: float, font_size: float, style: str = "") -> float:
    pdf.set_font("Helvetica", style, font_size)
    lines = _wrap_lines(pdf, w, text, line_h)
    return max(line_h, len(lines) * line_h)


def _table_col_widths(pdf: FPDF) -> list[float]:
    total = sum(_TABLE_COL_FR)
    return [pdf.epw * f / total for f in _TABLE_COL_FR]


class VigilReportPDF(FPDF):
    def __init__(self, report_id: str, framework_short: str, period_days: int):
        super().__init__()
        self.report_id = report_id
        self.framework_short = framework_short
        self.period_days = period_days

    def footer(self) -> None:
        self.set_y(-20)
        self.set_draw_color(228, 228, 231)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2.5)
        self.set_font("Helvetica", "", _FONT["footer"])
        self.set_text_color(113, 113, 122)
        self.cell(
            0,
            4,
            _s(
                f"Generated by Vigil . {self.framework_short} . Last {self.period_days} days . "
                f"Read-only evidence . Report ID: {self.report_id}"
            ),
            align="C",
        )
        self.ln(4)
        self.set_font("Helvetica", "", _FONT["footer"])
        self.set_text_color(161, 161, 170)
        self.cell(
            0,
            4,
            _s("Not a compliance attestation. Supports audit review only."),
            align="C",
        )
        self.set_y(-8)
        self.set_font("Helvetica", "", _FONT["footer"])
        self.set_text_color(161, 161, 170)
        self.cell(
            0,
            4,
            _s(
                f"{self.framework_short} . Last {self.period_days} days . "
                f"Page {self.page_no()}/{{nb}}"
            ),
            align="R",
        )


def _ensure_space(pdf: FPDF, needed: float) -> None:
    if pdf.get_y() + needed > _page_bottom(pdf):
        pdf.add_page()


def _section_heading_block_height(*, compact: bool = False) -> float:
    gap = 2 if compact else _SECTION_GAP
    return gap + (7 if compact else 8) + (1 if compact else 2)


def _open_section(
    pdf: FPDF,
    title: str,
    content_height: float,
    *,
    compact: bool = False,
    new_page: bool = False,
) -> None:
    """Start a section — heading stays with at least the first content block below it."""
    heading_h = _section_heading_block_height(compact=compact)
    total = heading_h + content_height
    if new_page:
        pdf.add_page()
    elif pdf.get_y() + total > _page_bottom(pdf):
        pdf.add_page()
    gap = 2 if compact else _SECTION_GAP
    pdf.ln(gap)
    pdf.set_font("Helvetica", "B", _FONT["h2"])
    pdf.set_text_color(24, 24, 27)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 7 if compact else 8, _s(title), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1 if compact else 2)


def _section_heading(
    pdf: FPDF,
    title: str,
    needed_after: float = 24,
    *,
    compact: bool = False,
    new_page: bool = False,
) -> None:
    """Legacy orphan guard — prefer _open_section when content height is known."""
    _open_section(pdf, title, needed_after, compact=compact, new_page=new_page)


def _draw_pill(
    pdf: FPDF,
    label: str,
    style: dict[str, Any],
    w: float | None = None,
    h: float = 6.5,
    *,
    font_size: float | None = None,
) -> None:
    pdf.set_font("Helvetica", "B", font_size or _FONT["badge"])
    if w is None:
        w = pdf.get_string_width(_s(label)) + 10
    x, y = pdf.get_x(), pdf.get_y()
    pdf.set_draw_color(*style["border"])
    pdf.set_fill_color(*style["fill"])
    pdf.rect(x, y + 0.2, w, h, style="FD")
    pdf.set_xy(x, y + 1.4)
    pdf.set_text_color(*style["text"])
    pdf.cell(w, 4, _s(label), align="C")
    pdf.set_xy(x + w + 2, y)


def _summary_card_height(pdf: FPDF, w: float, subtitle: str, *, compact: bool = False) -> float:
    line_h = 3.5 if compact else 4
    sub_h = _block_height(pdf, w - 8, subtitle, line_h, _FONT["footer"])
    if compact:
        return 10 + 4 + sub_h + 3
    return 13 + 5 + sub_h + 5


def _draw_summary_card(
    pdf: FPDF,
    x: float,
    y: float,
    w: float,
    h: float,
    value: str,
    title: str,
    subtitle: str,
    accent: tuple[int, int, int],
    *,
    compact: bool = False,
) -> None:
    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(228, 228, 231)
    pdf.rect(x, y, w, h, style="FD")
    pdf.set_fill_color(*accent)
    pdf.rect(x, y, 2, h, style="F")
    val_size = 14 if compact else 16
    val_y = 3 if compact else 4
    title_y = 11 if compact else 13
    sub_y = 15 if compact else 18
    pdf.set_xy(x + 5, y + val_y)
    pdf.set_font("Helvetica", "B", val_size)
    pdf.set_text_color(24, 24, 27)
    pdf.cell(w - 8, 7 if compact else 8, _s(value))
    pdf.set_xy(x + 5, y + title_y)
    pdf.set_font("Helvetica", "B", _FONT["label"])
    pdf.set_text_color(63, 63, 70)
    pdf.cell(w - 8, 4, _s(title))
    pdf.set_xy(x + 5, y + sub_y)
    pdf.set_font("Helvetica", "", _FONT["footer"])
    pdf.set_text_color(113, 113, 122)
    pdf.multi_cell(w - 8, 3.5 if compact else 4, _s(subtitle), align=_ALIGN)


def _draw_meta_card(pdf: FPDF, fields: list[tuple[str, str]], *, compact: bool = False) -> None:
    """Label/value rows with wrapping — no overlapping absolute blocks."""
    label_w = 42
    pad = _META_PAD if compact else _CARD_PAD
    value_w = pdf.epw - label_w - 2 * pad
    line_h = 4.5 if compact else 5
    row_gap = 2 if compact else 2.5

    row_heights: list[float] = []
    for _, value in fields:
        h = _block_height(pdf, value_w, value, line_h, _FONT["body"])
        row_heights.append(max(h, line_h) + row_gap)

    card_h = pad * 2 + sum(row_heights) - row_gap
    y0 = pdf.get_y()
    pdf.set_fill_color(249, 250, 251)
    pdf.set_draw_color(228, 228, 231)
    pdf.rect(pdf.l_margin, y0, pdf.epw, card_h, style="FD")

    y = y0 + pad
    for i, (label, value) in enumerate(fields):
        x_label = pdf.l_margin + pad
        x_value = pdf.l_margin + label_w
        pdf.set_xy(x_label, y)
        pdf.set_font("Helvetica", "B", _FONT["label"])
        pdf.set_text_color(113, 113, 122)
        pdf.cell(label_w - pad, line_h, _s(f"{label}:"))

        pdf.set_xy(x_value, y)
        pdf.set_font("Helvetica", "", _FONT["body"])
        pdf.set_text_color(39, 39, 42)
        pdf.multi_cell(value_w, line_h, _s(value), align=_ALIGN)
        y += row_heights[i]

    pdf.set_y(y0 + card_h + (3 if compact else 5))


def _friendly_resource_name(arn: str) -> str:
    """Short readable name for finding row title — full path goes on Resource line."""
    if arn.startswith("github://"):
        path = arn[len("github://") :].lstrip("/")
        if path.startswith("repo/"):
            path = path[5:]
        return path.rsplit("/", 1)[-1] or path
    if arn.startswith("gitlab://"):
        path = arn[len("gitlab://") :].lstrip("/")
        if path.startswith("repo/"):
            path = path[5:]
        return path.rsplit("/", 1)[-1] or path
    if arn.startswith("arn:aws:"):
        if ":role/" in arn:
            return arn.split(":role/", 1)[-1].rsplit("/", 1)[-1]
        if ":user/" in arn:
            return arn.split(":user/", 1)[-1].rsplit("/", 1)[-1]
        if ":policy/" in arn:
            return arn.split(":policy/", 1)[-1].rsplit("/", 1)[-1]
    if "/" in arn:
        name = arn.rsplit("/", 1)[-1]
        return name if len(name) <= 52 else _truncate_middle(name, 52)
    return _truncate_middle(arn, 52)


def _resource_label(arn: str) -> str:
    return _friendly_resource_name(arn)


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "medium").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _format_severity_summary(counts: dict[str, int]) -> str:
    if not counts:
        return "No severity breakdown"
    order = sorted(counts.keys(), key=lambda s: _SEV_PRIORITY.get(s, 99))
    return ", ".join(f"{s.capitalize()}: {counts[s]}" for s in order)


def _format_top_controls_detail(
    counts: dict[str, int],
    finding_count: int,
    evidence_label: str,
) -> str:
    fc_label = f"{finding_count} finding{'s' if finding_count != 1 else ''}"
    if not counts:
        sev_part = "No severity breakdown"
    else:
        order = sorted(counts.keys(), key=lambda s: _SEV_PRIORITY.get(s, 99))
        sev_part = " / ".join(f"{counts[s]} {s.capitalize()}" for s in order)
    return f"{fc_label} . {sev_part} . Evidence {evidence_label}"


def _control_review_priority(control: dict[str, Any]) -> tuple[int, int, int, int, str]:
    findings = control.get("findings") or []
    counts = _severity_counts(findings)
    finding_count = int(control.get("finding_count") or sum(counts.values()) or 0)
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    worst = min(_SEV_PRIORITY.get(s, 99) for s in counts) if counts else 99
    return (-finding_count, -critical, -high, worst, control["control_id"])


def _key_controls_for_review(
    control_results: list[dict[str, Any]],
    *,
    limit: int = _KEY_CONTROLS_LIMIT,
) -> list[dict[str, Any]]:
    review = [r for r in control_results if r.get("status") == "fail"]
    review.sort(key=_control_review_priority)
    return review[:limit]


def _fmt_date(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except ValueError:
        return iso[:10]


def _draw_labeled_line(
    pdf: FPDF,
    x: float,
    width: float,
    label: str,
    value: str,
    *,
    label_font: tuple[str, str, float] = ("Helvetica", "B", _FONT["meta"]),
    value_font: tuple[str, str, float] = ("Helvetica", "", _FONT["finding"]),
    label_color: tuple[int, int, int] = (63, 63, 70),
    value_color: tuple[int, int, int] = (63, 63, 70),
    line_h: float = _FINDING_LINE_H,
    wrap_value: bool = False,
) -> None:
    """Left-aligned label + value — never justified."""
    pdf.set_xy(x, pdf.get_y())
    pdf.set_font(label_font[0], label_font[1], label_font[2])
    pdf.set_text_color(*label_color)
    label_w = pdf.get_string_width(_s(label))
    pdf.cell(label_w, line_h, _s(label))
    pdf.set_font(value_font[0], value_font[1], value_font[2])
    pdf.set_text_color(*value_color)
    if wrap_value:
        lines = _wrap_lines(pdf, width - label_w, value, line_h)
        pdf.set_xy(x + label_w, pdf.get_y())
        for i, line in enumerate(lines):
            if i > 0:
                pdf.set_xy(x, pdf.get_y())
            pdf.cell(width if i > 0 else width - label_w, line_h, _s(line), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(width - label_w, line_h, _s(value), new_x="LMARGIN", new_y="NEXT")


def _draw_label_value(
    pdf: FPDF,
    x: float,
    label: str,
    value: str,
    width: float,
    *,
    value_color: tuple[int, int, int] = (63, 63, 70),
    line_h: float = 5,
) -> None:
    pdf.set_x(x)
    pdf.set_font("Helvetica", "B", _FONT["label"])
    pdf.set_text_color(82, 82, 91)
    pdf.cell(0, line_h, _s(label), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x)
    pdf.set_font("Helvetica", "", _FONT["body"])
    pdf.set_text_color(*value_color)
    pdf.multi_cell(width - _CARD_INNER_RPAD, line_h, _s(value), align=_ALIGN)


def _draw_severity_badge(
    pdf: FPDF,
    x: float,
    y: float,
    sev: str,
    *,
    col_w: float = _FINDING_BADGE_COL,
    badge_h: float = 6,
) -> None:
    sev_key = sev.lower()
    style = _SEVERITY_STYLE.get(sev_key, _SEVERITY_STYLE["medium"])
    pdf.set_draw_color(*style["border"])
    pdf.set_fill_color(*style["fill"])
    pdf.rect(x, y, col_w, badge_h, style="FD")
    pdf.set_xy(x, y + 1.5)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*style["text"])
    pdf.cell(col_w, 3.5, sev_key.upper(), align="C")


def _finding_content_lines(
    pdf: FPDF, finding: dict[str, Any], content_w: float
) -> tuple[str, str, tuple[str, str], str]:
    arn = finding.get("resource_arn") or ""
    resource = _friendly_resource_name(arn)
    issue = " ".join((finding.get("title") or "").split())
    resource_parts = _resource_line(pdf, arn, content_w)
    observed = (
        f"First seen {_fmt_date(finding.get('first_seen'))} | "
        f"Last seen {_fmt_date(finding.get('last_seen'))}"
    )
    return resource, issue, resource_parts, observed


def _estimate_finding_height(pdf: FPDF, finding: dict[str, Any], width: float) -> float:
    content_w = width - _FINDING_BADGE_COL - _FINDING_CONTENT_GAP - _FINDING_ROW_PAD * 2
    _, issue, _, _ = _finding_content_lines(pdf, finding, content_w)
    pdf.set_font("Helvetica", "B", _FONT["finding_meta"])
    issue_w = content_w - pdf.get_string_width(_s("Issue: "))
    h = _FINDING_ROW_PAD * 2 + 7
    h += _block_height(pdf, issue_w, issue, _FINDING_LINE_H, _FONT["finding"])
    h += _FINDING_LINE_H * 2
    return h + _FINDING_ROW_GAP


def _draw_finding_row(pdf: FPDF, finding: dict[str, Any], width: float, base_x: float) -> None:
    sev = (finding.get("severity") or "medium").lower()
    inner_w = width - 4
    badge_x = base_x + _FINDING_ROW_PAD
    content_x = badge_x + _FINDING_BADGE_COL + _FINDING_CONTENT_GAP
    content_w = inner_w - _FINDING_BADGE_COL - _FINDING_CONTENT_GAP - _FINDING_ROW_PAD * 2
    row_h = _estimate_finding_height(pdf, finding, width)
    resource, issue, resource_parts, observed_val = _finding_content_lines(pdf, finding, content_w)

    y0 = pdf.get_y()
    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(228, 228, 231)
    pdf.rect(base_x, y0, inner_w, row_h, style="FD")

    content_top = y0 + _FINDING_ROW_PAD
    _draw_severity_badge(pdf, badge_x, content_top, sev)

    pdf.set_xy(content_x, content_top)
    pdf.set_font("Helvetica", "B", _FONT["finding_title"])
    pdf.set_text_color(39, 39, 42)
    pdf.cell(content_w, 7, _s(resource), new_x="END", new_y="NEXT")
    pdf.set_x(content_x)

    _draw_labeled_line(
        pdf, content_x, content_w, "Issue: ", issue,
        label_font=("Helvetica", "B", _FONT["finding_meta"]),
        value_font=("Helvetica", "", _FONT["finding"]),
        wrap_value=True,
    )
    pdf.set_x(content_x)

    res_label, res_value = resource_parts
    _draw_labeled_line(
        pdf, content_x, content_w, res_label, res_value,
        label_font=("Helvetica", "B", _FONT["finding_meta"]),
        label_color=_RESOURCE_LABEL_COLOR,
        value_font=("Helvetica", "", 9.2),
        value_color=(75, 85, 99),
    )
    pdf.set_x(content_x)

    _draw_labeled_line(
        pdf, content_x, content_w, "Observed: ", observed_val,
        label_font=("Helvetica", "B", _FONT["finding_meta"]),
        label_color=_RESOURCE_LABEL_COLOR,
        value_font=("Helvetica", "", _FONT["finding_meta"]),
        value_color=(107, 114, 128),
    )

    pdf.set_y(y0 + row_h + _FINDING_ROW_GAP)


def _estimate_review_card_height(pdf: FPDF, control: dict[str, Any]) -> float:
    findings = control.get("findings") or []
    inner_w = pdf.epw - 2 * _CARD_PAD
    text_w = inner_w - _CARD_INNER_RPAD
    h = _CARD_PAD + 10
    h += 5 + _block_height(pdf, text_w, control.get("description") or "", 5.5, _FONT["body"]) + 3
    reason = control.get("review_reason") or control.get("status_note") or ""
    h += 5 + _block_height(pdf, text_w, reason, 5.5, _FONT["body"]) + 3
    counts = _severity_counts(findings)
    if counts:
        h += 5 + 5 + 3
    if findings:
        h += 5 + 1
        for f in findings[:3]:
            h += _estimate_finding_height(pdf, f, inner_w)
        if len(findings) > 3:
            h += 5
    h += 3 + 5 + 5 + _CARD_BOTTOM_PAD + _CARD_PAD
    return h


def _draw_review_card(pdf: FPDF, control: dict[str, Any]) -> None:
    findings = control.get("findings") or []
    inner_w = pdf.epw - 2 * _CARD_PAD
    text_w = inner_w - _CARD_INNER_RPAD
    est_h = _estimate_review_card_height(pdf, control)
    _ensure_space(pdf, est_h)

    y0 = pdf.get_y()
    inner_x = pdf.l_margin + _CARD_PAD

    pdf.set_fill_color(252, 252, 253)
    pdf.set_draw_color(228, 228, 231)
    pdf.rect(pdf.l_margin, y0, pdf.epw, est_h, style="FD")
    pdf.set_fill_color(245, 158, 11)
    pdf.rect(pdf.l_margin, y0, 2.5, est_h, style="F")

    pdf.set_xy(inner_x, y0 + _CARD_PAD)
    pdf.set_font("Helvetica", "B", _FONT["h3"])
    pdf.set_text_color(24, 24, 27)
    title = _s(f"{control['control_id']} {control['title']}")
    pdf.cell(inner_w - 34, 7, title)

    badge_w = 30
    pdf.set_xy(pdf.w - pdf.r_margin - _CARD_PAD - badge_w, y0 + _CARD_PAD + 0.5)
    _draw_pill(pdf, "Needs Review", _CONTROL_STATUS["fail"], w=badge_w, h=6.5)

    pdf.set_xy(inner_x, y0 + _CARD_PAD + 10)
    _draw_label_value(pdf, inner_x, "Objective", control.get("description") or "", text_w)
    pdf.ln(2)
    _draw_label_value(
        pdf,
        inner_x,
        "Reason",
        control.get("review_reason") or control.get("status_note") or "",
        text_w,
        value_color=(113, 63, 18),
    )
    pdf.ln(2)

    counts = _severity_counts(findings)
    if counts:
        pdf.set_x(inner_x)
        pdf.set_font("Helvetica", "B", _FONT["label"])
        pdf.set_text_color(82, 82, 91)
        pdf.cell(0, 5, "Findings by severity", new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(inner_x)
        parts = [f"{k.capitalize()}: {v}" for k, v in sorted(counts.items())]
        pdf.set_font("Helvetica", "", _FONT["body"])
        pdf.set_text_color(63, 63, 70)
        pdf.cell(0, 5, ", ".join(parts), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    if findings:
        pdf.set_x(inner_x)
        pdf.set_font("Helvetica", "B", _FONT["label"])
        pdf.set_text_color(82, 82, 91)
        pdf.cell(0, 5, "Top findings", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        for f in findings[:3]:
            _draw_finding_row(pdf, f, inner_w, inner_x)
        if len(findings) > 3:
            pdf.set_x(inner_x)
            pdf.set_font("Helvetica", "I", _FONT["footer"])
            pdf.set_text_color(113, 113, 122)
            pdf.cell(
                0,
                5,
                _s(f"+ {len(findings) - 3} more findings in controls/{control['control_id']}/findings.json"),
                new_x="LMARGIN",
                new_y="NEXT",
            )

    cid = control["control_id"]
    pdf.ln(2)
    pdf.set_x(inner_x)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(82, 82, 91)
    folder_label = "Evidence folder: "
    pdf.cell(pdf.get_string_width(_s(folder_label)), 5, _s(folder_label))
    pdf.set_font("Courier", "B", 9)
    pdf.set_text_color(39, 39, 42)
    pdf.cell(0, 5, _s(f"controls/{cid}/"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(inner_x)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(82, 82, 91)
    pdf.cell(
        0,
        5,
        _s("Artifacts: findings.json, snapshots.json, exceptions.json, summary.json"),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(_CARD_BOTTOM_PAD)

    y_end = pdf.get_y()
    actual_h = y_end - y0
    if actual_h < est_h:
        pdf.set_fill_color(255, 255, 255)
        pdf.rect(pdf.l_margin, y0 + actual_h, pdf.epw, est_h - actual_h, style="F")
        pdf.set_draw_color(228, 228, 231)
        pdf.line(pdf.l_margin, y0 + actual_h, pdf.w - pdf.r_margin, y0 + actual_h)
    elif actual_h > est_h:
        extra = actual_h - est_h
        pdf.set_fill_color(252, 252, 253)
        pdf.rect(pdf.l_margin, y0 + est_h, pdf.epw, extra, style="FD")
        pdf.set_fill_color(245, 158, 11)
        pdf.rect(pdf.l_margin, y0 + est_h, 2.5, extra, style="F")
        pdf.set_draw_color(228, 228, 231)
        pdf.line(pdf.l_margin, y0 + est_h, pdf.w - pdf.r_margin, y0 + est_h)
        est_h = actual_h

    pdf.set_draw_color(228, 228, 231)
    pdf.rect(pdf.l_margin, y0, pdf.epw, est_h, style="D")
    pdf.set_y(y_end + _CARD_GAP)


def _estimate_key_controls_height(pdf: FPDF, controls: list[dict[str, Any]]) -> float:
    if not controls:
        return 14
    return 8 + len(controls) * 20 + 6


def _draw_key_controls_requiring_review(pdf: FPDF, controls: list[dict[str, Any]]) -> None:
    """Executive top-N list for page 1 — where to look first."""
    if not controls:
        pdf.set_font("Helvetica", "", _FONT["body"])
        pdf.set_text_color(82, 82, 91)
        pdf.set_x(pdf.l_margin)
        pdf.cell(0, 6, _s("No controls currently require review."), new_x="LMARGIN", new_y="NEXT")
        return

    y0 = pdf.get_y()
    row_h = 20
    card_h = len(controls) * row_h + 6
    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(228, 228, 231)
    pdf.rect(pdf.l_margin, y0, pdf.epw, card_h, style="FD")

    inner_w = pdf.epw - 10
    for idx, control in enumerate(controls):
        findings = control.get("findings") or []
        counts = _severity_counts(findings)
        finding_count = int(control.get("finding_count") or sum(counts.values()) or 0)
        objective = _objective_text(control.get("title") or "")
        ev_style = _EVIDENCE_STATUS.get(
            control.get("evidence_status", "missing"), _EVIDENCE_STATUS["missing"]
        )
        detail = _format_top_controls_detail(counts, finding_count, ev_style["label"])
        y_row = y0 + 3 + idx * row_h
        fill = (252, 252, 253) if idx % 2 else (255, 255, 255)
        pdf.set_fill_color(*fill)
        pdf.rect(pdf.l_margin, y_row, pdf.epw, row_h, style="F")

        x = pdf.l_margin + 5
        pdf.set_xy(x, y_row + 3)
        pdf.set_font("Helvetica", "B", _FONT["body"])
        pdf.set_text_color(24, 24, 27)
        title = f"{control['control_id']}  {objective}"
        if len(title) > 88:
            title = title[:85] + "..."
        pdf.cell(inner_w, 6, _s(title))

        pdf.set_xy(x, y_row + 11)
        pdf.set_font("Helvetica", "", _FONT["label"])
        pdf.set_text_color(63, 63, 70)
        pdf.cell(inner_w, 5, _s(detail))

    pdf.set_y(y0 + card_h + 4)


def _estimate_evidence_sources_card_height(pdf: FPDF, sources: list[str]) -> float:
    pad = _CARD_PAD
    col_gap = 8
    col_w = (pdf.epw - 2 * pad - col_gap) / 2
    line_h = 5
    sources_text = ", ".join(sources)
    artifacts_text = (
        "Raw JSON snapshots, findings.json, timeline.csv, source_manifest.json, "
        "control summaries, exception records"
    )
    left_h = 6 + _block_height(pdf, col_w, sources_text, line_h, _FONT["body"]) + 6
    left_h += _block_height(pdf, col_w, "Read-only API access", line_h, _FONT["body"])
    right_h = 6 + _block_height(pdf, col_w, artifacts_text, line_h, _FONT["body"])
    return pad * 2 + max(left_h, right_h)


def _draw_evidence_sources_card(pdf: FPDF, sources: list[str], *, page_check: bool = True) -> None:
    pad = _CARD_PAD
    col_gap = 8
    col_w = (pdf.epw - 2 * pad - col_gap) / 2
    line_h = 5

    sources_text = ", ".join(sources)
    artifacts_text = (
        "Raw JSON snapshots, findings.json, timeline.csv, source_manifest.json, "
        "control summaries, exception records"
    )

    left_h = (
        6
        + _block_height(pdf, col_w, sources_text, line_h, _FONT["body"])
        + 8
        + _block_height(pdf, col_w, "Read-only API access", line_h, _FONT["body"])
    )
    right_h = 6 + _block_height(pdf, col_w, artifacts_text, line_h, _FONT["body"])
    card_h = pad * 2 + max(left_h, right_h)

    if page_check:
        _ensure_space(pdf, card_h + 10)
    y0 = pdf.get_y()
    pdf.set_fill_color(249, 250, 251)
    pdf.set_draw_color(228, 228, 231)
    pdf.rect(pdf.l_margin, y0, pdf.epw, card_h, style="FD")

    left_x = pdf.l_margin + pad
    right_x = left_x + col_w + col_gap
    y = y0 + pad

    pdf.set_xy(left_x, y)
    pdf.set_font("Helvetica", "B", _FONT["h3"])
    pdf.set_text_color(24, 24, 27)
    pdf.cell(col_w, 6, "Source systems", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(left_x)
    pdf.set_font("Helvetica", "", _FONT["body"])
    pdf.set_text_color(63, 63, 70)
    pdf.multi_cell(col_w, line_h, _s(sources_text), align=_ALIGN)
    pdf.ln(2)
    pdf.set_x(left_x)
    pdf.set_font("Helvetica", "", _FONT["body"])
    pdf.multi_cell(col_w, line_h, _s("Read-only API access"), align=_ALIGN)

    pdf.set_xy(right_x, y)
    pdf.set_font("Helvetica", "B", _FONT["h3"])
    pdf.set_text_color(24, 24, 27)
    pdf.cell(col_w, 6, "Included artifacts", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(right_x)
    pdf.set_font("Helvetica", "", _FONT["body"])
    pdf.set_text_color(63, 63, 70)
    pdf.multi_cell(col_w, line_h, _s(artifacts_text), align=_ALIGN)

    pdf.set_y(y0 + card_h + 6)


def _draw_usage_and_limitations(pdf: FPDF) -> None:
    _ensure_space(pdf, 48)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", _FONT["h3"])
    pdf.set_text_color(24, 24, 27)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 6, "How to use this report", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    steps = [
        "Review controls marked Needs Review.",
        "Open the referenced control folder in the ZIP.",
        "Validate raw JSON/CSV evidence.",
        "Document exceptions or remediation where needed.",
    ]
    pdf.set_font("Helvetica", "", _FONT["body"])
    pdf.set_text_color(63, 63, 70)
    for i, step in enumerate(steps, 1):
        pdf.set_x(pdf.l_margin + 2)
        pdf.cell(0, 5, _s(f"{i}. {step}"), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(3)
    pdf.set_font("Helvetica", "B", _FONT["h3"])
    pdf.set_text_color(24, 24, 27)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 6, "Limitations", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", _FONT["body"])
    pdf.set_text_color(82, 82, 91)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(
        pdf.epw,
        5,
        _s(
            "This report reflects data available from connected source systems during the selected "
            "audit period. It supports audit review but does not replace auditor judgment or "
            "company policy evidence."
        ),
        align=_ALIGN,
    )


def _estimate_table_row_heights(
    pdf: FPDF,
    control_results: list[dict[str, Any]],
    col_w: list[float],
    *,
    compact: bool = False,
) -> list[float]:
    if compact:
        return [float(_TABLE_ROW_COMPACT)] * len(control_results)
    heights: list[float] = []
    for r in control_results:
        objective = _objective_text(r["title"])
        obj_h = _block_height(pdf, col_w[1] - 2, objective, 5, _FONT["table"])
        heights.append(max(11, obj_h + 3))
    return heights


def _draw_control_table_header(
    pdf: FPDF,
    col_w: list[float],
    *,
    continued: bool = False,
) -> float:
    header_h = _TABLE_HEADER_H
    if continued:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(24, 24, 27)
        pdf.set_x(pdf.l_margin)
        pdf.cell(0, 6, "Control Overview, continued", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    headers: list[tuple[str, str]] = [
        ("Control", "L"),
        ("Objective", "L"),
        ("Control\nStatus", "C"),
        ("Evidence\nStatus", "C"),
        ("Open\nFindings", "C"),
    ]
    x = pdf.l_margin
    y_header = pdf.get_y()
    pdf.set_fill_color(248, 250, 252)
    pdf.set_draw_color(228, 228, 231)
    for i, (label, align) in enumerate(headers):
        pdf.rect(x, y_header, col_w[i], header_h, style="FD")
        pdf.set_xy(x, y_header + 1.4)
        pdf.set_font("Helvetica", "B", _FONT["table"] - 0.5)
        pdf.set_text_color(63, 63, 70)
        pdf.multi_cell(col_w[i], 4, _s(label), align=align)
        x += col_w[i]
    pdf.line(pdf.l_margin, y_header + header_h, pdf.l_margin + sum(col_w), y_header + header_h)
    pdf.set_y(y_header + header_h)
    return header_h


def _draw_control_overview_table(
    pdf: FPDF,
    control_results: list[dict[str, Any]],
    *,
    compact: bool | None = None,
) -> None:
    col_w = _table_col_widths(pdf)
    if compact is None:
        compact = len(control_results) > 20

    row_heights = _estimate_table_row_heights(pdf, control_results, col_w, compact=compact)

    _draw_control_table_header(pdf, col_w)
    bottom = _page_bottom(pdf)

    for idx, r in enumerate(control_results):
        row_h = row_heights[idx]

        if pdf.get_y() + row_h > bottom:
            pdf.add_page()
            _draw_control_table_header(pdf, col_w, continued=True)

        fill = idx % 2 == 0
        bg = (255, 255, 255) if fill else (252, 252, 253)
        pdf.set_fill_color(*bg)
        y_row = pdf.get_y()
        objective = _short_objective(r["title"], 42 if compact else 999)

        pdf.set_xy(pdf.l_margin, y_row)
        pdf.set_font("Helvetica", "B", _FONT["table"])
        pdf.set_text_color(39, 39, 42)
        pdf.cell(col_w[0], row_h, _s(r["control_id"]), border=0, fill=fill)

        pdf.set_xy(pdf.l_margin + col_w[0], y_row + 1.2)
        pdf.set_font("Helvetica", "", _FONT["table"])
        pdf.set_text_color(63, 63, 70)
        if compact:
            pdf.cell(col_w[1] - 1, row_h - 2, _s(objective), border=0, fill=fill)
        else:
            pdf.multi_cell(col_w[1], 5, _s(_objective_text(r["title"])), align=_ALIGN)

        pill_h = 6 if compact else 6.5
        pill_y = y_row + max(1.0, (row_h - pill_h) / 2)
        ctrl_style = _CONTROL_STATUS.get(r["status"], _CONTROL_STATUS["no_data"])
        pdf.set_xy(pdf.l_margin + col_w[0] + col_w[1] + 1, pill_y)
        _draw_pill(pdf, ctrl_style["label"], ctrl_style, w=col_w[2] - 2, h=pill_h)

        ev_style = _EVIDENCE_STATUS.get(r.get("evidence_status", "missing"), _EVIDENCE_STATUS["missing"])
        pdf.set_xy(pdf.l_margin + sum(col_w[:3]) + 1, pill_y)
        _draw_pill(pdf, ev_style["label"], ev_style, w=col_w[3] - 2, h=pill_h)

        pdf.set_xy(pdf.l_margin + sum(col_w[:4]), y_row)
        pdf.set_font("Helvetica", "B", _FONT["table"])
        pdf.set_text_color(39, 39, 42)
        pdf.cell(col_w[4], row_h, str(r["finding_count"]), border=0, fill=fill, align="C")
        pdf.set_y(y_row + row_h)


def build_pdf(
    acc: AwsAccount,
    framework: str,
    period_days: int,
    generated_at: datetime,
    control_results: list[dict[str, Any]],
    *,
    since: datetime | None = None,
    evidence_sources: list[str] | None = None,
    report_id: str | None = None,
) -> bytes:
    rid = report_id or "SAMPLE"
    fw_short = _FRAMEWORK_SHORT.get(framework, framework.upper())
    pdf = VigilReportPDF(rid, fw_short, period_days)
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=_PAGE_BOTTOM)
    pdf.set_margins(18, 12, 18)
    pdf.add_page()

    pack_badge = _FRAMEWORK_PACK_BADGE.get(framework, "Compliance Evidence Pack")
    period_end = generated_at.date()
    period_start = since.date() if since else period_end
    sources = evidence_sources or ["AWS IAM", "AWS CloudTrail", "AWS Config"]
    sources_display = ", ".join(sources)

    _draw_report_header(
        pdf,
        pack_badge,
        _FRAMEWORK_LABELS.get(framework, framework.upper()),
    )

    _draw_meta_card(
        pdf,
        [
            ("Account", f"{_s(acc.label)} ({acc.account_id or 'unknown'})"),
            ("Audit period", f"{period_start} to {period_end} ({period_days} days)"),
            ("Generated", generated_at.strftime("%Y-%m-%d %H:%M UTC")),
            ("Report ID", rid),
            ("Evidence sources", sources_display),
            ("Collection mode", "Read-only API collection"),
        ],
        compact=True,
    )

    passed = sum(1 for r in control_results if r["status"] == "pass")
    failed = sum(1 for r in control_results if r["status"] == "fail")
    no_data = sum(1 for r in control_results if r["status"] == "no_data")
    total = len(control_results)
    score_pct = round((passed / total) * 100) if total else 0

    _section_heading(pdf, "Executive Summary", needed_after=24, compact=True)
    card_w = (pdf.epw - 9) / 4
    summaries = [
        (f"{score_pct}%", "Pass rate", f"{passed} of {total} controls passing", _SUMMARY_ACCENTS["pass"]),
        (str(passed), "Passed controls", "No open findings", _SUMMARY_ACCENTS["pass"]),
        (str(failed), "Needs review", "Open findings mapped to controls", _SUMMARY_ACCENTS["review"]),
        (str(no_data), "No data", "Not evaluated", _SUMMARY_ACCENTS["neutral"]),
    ]
    card_h = max(_summary_card_height(pdf, card_w, s[2], compact=True) for s in summaries)
    y0 = pdf.get_y()
    x = pdf.l_margin
    for value, title, subtitle, accent in summaries:
        _draw_summary_card(
            pdf, x, y0, card_w, card_h, value, title, subtitle, accent, compact=True
        )
        x += card_w + 3
    pdf.set_y(y0 + card_h + 3)

    _SUMMARY_NOTE = (
        "Control status reflects open findings. Evidence status reflects whether source "
        "snapshots were collected, independent of pass or fail."
    )
    pdf.set_font("Helvetica", "", _FONT["footer"])
    pdf.set_text_color(113, 113, 122)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, 4, _s(_SUMMARY_NOTE), align=_ALIGN)
    pdf.ln(2)

    key_controls = _key_controls_for_review(control_results)
    key_h = _estimate_key_controls_height(pdf, key_controls)
    _section_heading(
        pdf,
        "Top Controls Requiring Review",
        needed_after=min(key_h, 40),
        compact=True,
    )
    _draw_key_controls_requiring_review(pdf, key_controls)
    if len(key_controls) == _KEY_CONTROLS_LIMIT:
        pdf.set_font("Helvetica", "I", _FONT["footer"])
        pdf.set_text_color(113, 113, 122)
        pdf.set_x(pdf.l_margin)
        pdf.cell(
            0,
            4,
            _s("Showing top 5 by open finding count. See Control Overview for the full list."),
            new_x="LMARGIN",
            new_y="NEXT",
        )

    review_controls = [r for r in control_results if r["status"] == "fail"]

    _section_heading(
        pdf,
        "Control Overview",
        needed_after=_TABLE_HEADER_H + _TABLE_ROW_COMPACT,
        new_page=True,
    )
    _draw_control_overview_table(pdf, control_results)

    if review_controls:
        first_card_h = _estimate_review_card_height(pdf, review_controls[0])
        heading_h = _section_heading_block_height(compact=False)
        remaining = _page_bottom(pdf) - pdf.get_y()
        _open_section(
            pdf,
            "Controls Requiring Review",
            first_card_h,
            new_page=remaining < heading_h + first_card_h,
        )
        for r in review_controls:
            _draw_review_card(pdf, r)

    sources_card_h = _estimate_evidence_sources_card_height(pdf, sources)
    _open_section(pdf, "Evidence Sources", sources_card_h + 52, new_page=True)
    _draw_evidence_sources_card(pdf, sources, page_check=False)
    _draw_usage_and_limitations(pdf)

    return bytes(pdf.output())
