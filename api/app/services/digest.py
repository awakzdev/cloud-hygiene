"""Weekly IAM hygiene digest email via Resend."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from app.core.config import get_settings

log = structlog.get_logger()
settings = get_settings()

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def send_digest(
    to: str,
    org_name: str,
    account_label: str,
    open_findings: list[dict[str, Any]],
    new_this_week: list[dict[str, Any]],
    resolved_this_week: int,
) -> bool:
    """Send weekly digest to a single recipient. Returns True on success."""
    if not settings.RESEND_API_KEY:
        log.info("digest.skipped", reason="RESEND_API_KEY not set", to=to)
        return False

    subject = _subject(open_findings)
    html = _html(org_name, account_label, open_findings, new_this_week, resolved_this_week)
    text = _text(org_name, account_label, open_findings, new_this_week, resolved_this_week)

    try:
        resp = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
            json={
                "from": settings.DIGEST_FROM,
                "to": [to],
                "subject": subject,
                "html": html,
                "text": text,
            },
            timeout=10,
        )
        resp.raise_for_status()
        log.info("digest.sent", to=to, status=resp.status_code)
        return True
    except Exception as e:  # noqa: BLE001
        log.error("digest.failed", to=to, error=str(e))
        return False


def _subject(open_findings: list[dict]) -> str:
    crit_high = sum(1 for f in open_findings if f["severity"] in ("critical", "high"))
    total = len(open_findings)
    if crit_high:
        return f"Vigil: {crit_high} critical/high finding{'s' if crit_high != 1 else ''} need attention"
    if total:
        return f"Vigil: {total} open finding{'s' if total != 1 else ''} — weekly digest"
    return "Vigil: No open findings — all clear"


def _html(
    org_name: str,
    account_label: str,
    open_findings: list[dict],
    new_this_week: list[dict],
    resolved_this_week: int,
) -> str:
    top = sorted(open_findings, key=lambda f: (-f["risk_score"],))[:10]

    rows_html = ""
    for f in top:
        sev = f["severity"]
        emoji = _SEV_EMOJI.get(sev, "")
        rows_html += f"""
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;font-size:13px;color:#18181b">
            {emoji} {f['title']}
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;font-size:12px;color:#71717a;font-family:monospace">
            {f['resource_arn'][-60:] if len(f['resource_arn']) > 60 else f['resource_arn']}
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;font-size:12px;font-weight:600;color:#dc2626;text-align:right">
            {f['risk_score']}
          </td>
        </tr>"""

    new_badge = f'<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600">{len(new_this_week)} new this week</span>' if new_this_week else ""
    resolved_badge = f'<span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600">{resolved_this_week} resolved</span>' if resolved_this_week else ""

    crit_high = sum(1 for f in open_findings if f["severity"] in ("critical", "high"))
    posture_score = max(0, min(100, 100 - crit_high * 10 - sum(1 for f in open_findings if f["severity"] == "medium") * 3))
    score_color = "#16a34a" if posture_score >= 80 else "#f59e0b" if posture_score >= 60 else "#dc2626"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;margin:0;padding:20px">
  <div style="max-width:600px;margin:0 auto;background:white;border-radius:12px;overflow:hidden;border:1px solid #e4e4e7">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0f172a,#0d1424);padding:24px 32px">
      <div style="color:white;font-size:20px;font-weight:700;letter-spacing:-0.3px">Vigil</div>
      <div style="color:#94a3b8;font-size:13px;margin-top:2px">Weekly Security Digest</div>
    </div>

    <!-- Summary bar -->
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border-bottom:1px solid #e4e4e7">
      <tr>
        <td style="padding:28px 24px 28px 32px;width:80px;text-align:center;vertical-align:middle">
          <div style="font-size:42px;font-weight:800;color:{score_color};line-height:1">{posture_score}</div>
          <div style="font-size:11px;color:#71717a;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;margin-top:6px">Posture Score</div>
        </td>
        <td style="padding:28px 8px;width:1px;vertical-align:middle">
          <div style="width:1px;height:52px;background:#e4e4e7"></div>
        </td>
        <td style="padding:28px 32px 28px 24px;vertical-align:middle">
          <div style="font-size:15px;color:#18181b;font-weight:600">{account_label}</div>
          <div style="font-size:12px;color:#71717a;margin-top:5px">{len(open_findings)} open findings total</div>
          <div style="margin-top:10px">{new_badge}&nbsp;&nbsp;{resolved_badge}</div>
        </td>
      </tr>
    </table>

    <!-- Top findings table -->
    <div style="padding:24px 32px">
      <div style="font-size:14px;font-weight:600;color:#18181b;margin-bottom:12px">
        Top open risks
        {f'<span style="color:#71717a;font-weight:400;font-size:13px"> — showing {len(top)} of {len(open_findings)}</span>' if len(open_findings) > len(top) else ''}
      </div>
      {'<div style="color:#71717a;font-size:13px;padding:16px 0">No open findings this week.</div>' if not top else f'''
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr>
            <th style="text-align:left;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:#71717a;background:#f9fafb;border-bottom:1px solid #e4e4e7">Finding</th>
            <th style="text-align:left;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:#71717a;background:#f9fafb;border-bottom:1px solid #e4e4e7">Resource</th>
            <th style="text-align:right;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:#71717a;background:#f9fafb;border-bottom:1px solid #e4e4e7">Score</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>'''}
    </div>

    <!-- CTA -->
    <div style="padding:0 32px 28px">
      <a href="{settings.API_PUBLIC_URL.replace(':8000', ':5173') if '8000' in settings.API_PUBLIC_URL else settings.API_PUBLIC_URL}/findings"
         style="display:inline-block;background:#18181b;color:white;padding:10px 22px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none">
        View all findings →
      </a>
    </div>

    <!-- Footer -->
    <div style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e4e4e7">
      <div style="font-size:11px;color:#a1a1aa">
        Vigil weekly digest for {org_name} · {datetime.now(timezone.utc).strftime('%B %d, %Y')} ·
        <a href="{settings.API_PUBLIC_URL.replace(':8000', ':5173') if '8000' in settings.API_PUBLIC_URL else settings.API_PUBLIC_URL}/settings" style="color:#71717a">Unsubscribe</a>
      </div>
    </div>
  </div>
</body>
</html>"""


def _text(
    org_name: str,
    account_label: str,
    open_findings: list[dict],
    new_this_week: list[dict],
    resolved_this_week: int,
) -> str:
    lines = [
        f"Vigil — Weekly Security Digest for {org_name}",
        f"Account: {account_label}",
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "",
        f"Open findings: {len(open_findings)}",
        f"New this week: {len(new_this_week)}",
        f"Resolved this week: {resolved_this_week}",
        "",
        "TOP OPEN RISKS",
        "=" * 40,
    ]
    top = sorted(open_findings, key=lambda f: -f["risk_score"])[:10]
    for f in top:
        lines.append(f"[{f['severity'].upper()}] {f['title']}")
        lines.append(f"  {f['resource_arn']}")
        lines.append(f"  Score: {f['risk_score']}")
        lines.append("")
    return "\n".join(lines)
