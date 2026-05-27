"""Tests for PDF evidence report generation."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace


def test_build_pdf_generates_bytes_with_review_section():
    from app.services.pdf_report import build_pdf

    acc = SimpleNamespace(label="Demo", account_id="123456789012")
    now = datetime.now(timezone.utc)
    results = [
        {
            "control_id": "CC6.3",
            "title": "Access Reviews",
            "description": "Access privileges are reviewed and restricted.",
            "guidance": "",
            "status": "fail",
            "evidence_status": "complete",
            "finding_count": 2,
            "review_reason": "2 open findings mapped to this control.",
            "findings": [
                {
                    "severity": "high",
                    "title": 'Wildcard Action "*" in inline policy',
                    "resource_arn": "arn:aws:iam::123:role/dev-unrestricted",
                    "first_seen": now.isoformat(),
                    "last_seen": now.isoformat(),
                }
            ],
        },
        {
            "control_id": "CC6.1",
            "title": "Logical Access",
            "description": "Logical access controls.",
            "guidance": "",
            "status": "pass",
            "evidence_status": "complete",
            "finding_count": 0,
            "findings": [],
            "review_reason": "No open findings mapped to this control.",
        },
    ]
    pdf = build_pdf(
        acc,
        "soc2",
        90,
        now,
        results,
        since=now,
        evidence_sources=["AWS IAM", "GitHub"],
        report_id="TESTREPORT01",
    )
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 3000
