"""Resolve the caller's IP for audit/UI helpers (e.g. remediation CLI)."""

from __future__ import annotations

from fastapi import Request

from app.core.config import get_settings


def client_ip_from_request(request: Request) -> str | None:
    if get_settings().APP_ENV != "dev":
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None
