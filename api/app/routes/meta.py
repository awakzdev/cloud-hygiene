from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.core.client_ip import client_ip_from_request

router = APIRouter()


class ClientIpOut(BaseModel):
    ip: str | None


@router.get("/client-ip", response_model=ClientIpOut)
def get_client_ip(request: Request) -> ClientIpOut:
    """Public IP of the browser session (for copy-paste remediation commands)."""
    return ClientIpOut(ip=client_ip_from_request(request))
