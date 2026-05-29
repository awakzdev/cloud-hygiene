import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.ratelimit import limiter

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.core.client_ip import client_ip_from_request
from app.routes import accounts, findings, auth, auth_oauth, github_integration, gitlab_integration, settings as settings_router
from app.routes import controls, exports, meta, public

log = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Seed compliance controls on every startup (idempotent upsert)
    try:
        from app.services.seed_controls import seed_controls
        db = SessionLocal()
        n = seed_controls(db)
        db.close()
        if n:
            log.info("controls.seeded", count=n)
    except Exception:
        log.exception("controls.seed_failed")
    yield


app = FastAPI(title="Vigil API", version="0.1.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.APP_ENV == "dev" else [settings.FRONTEND_URL],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.APP_ENV != "dev":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Attach a request-id to every request, log start+end with timing.

    - Honours an inbound `X-Request-Id` header (proxy passthrough) if present
      and well-formed; otherwise generates a UUID4.
    - Echoes the id back on the response as `X-Request-Id` so clients can
      correlate.
    - Binds the id to structlog's contextvars so any log line emitted during
      this request automatically carries `request_id=`.
    - Emits a single `http.request` log line per request with method, path,
      status, duration_ms, and remote_addr. Health checks are silenced.
    """

    _MAX_ID_LEN = 64

    async def dispatch(self, request: Request, call_next) -> Response:
        inbound = request.headers.get("x-request-id", "")
        if inbound and 1 <= len(inbound) <= self._MAX_ID_LEN and inbound.replace("-", "").isalnum():
            request_id = inbound
        else:
            request_id = uuid.uuid4().hex

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            log.exception(
                "http.request_failed",
                method=request.method,
                path=request.url.path,
            )
            raise
        finally:
            duration_ms = int((time.perf_counter() - start) * 1000)
            # silence health-check noise
            if request.url.path not in ("/healthz",):
                log.info(
                    "http.request",
                    method=request.method,
                    path=request.url.path,
                    status=status_code,
                    duration_ms=duration_ms,
                    remote=client_ip_from_request(request),
                )
            # tag the response so clients/proxies can correlate
            try:
                response.headers["X-Request-Id"] = request_id  # type: ignore[unbound-local]
            except Exception:  # noqa: BLE001
                pass
            structlog.contextvars.unbind_contextvars("request_id")


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)


@app.get("/healthz")
def healthz():
    return {"ok": True, "env": settings.APP_ENV}


app.include_router(auth.router, prefix="/v1/auth", tags=["auth"])
app.include_router(auth_oauth.router, prefix="/v1/auth", tags=["auth"])
app.include_router(accounts.router, prefix="/v1/accounts", tags=["accounts"])
app.include_router(findings.router, prefix="/v1/findings", tags=["findings"])
app.include_router(settings_router.router, prefix="/v1/settings", tags=["settings"])
app.include_router(controls.router, prefix="/v1/controls", tags=["controls"])
app.include_router(exports.router, prefix="/v1/exports", tags=["exports"])
app.include_router(meta.router, prefix="/v1/meta", tags=["meta"])
app.include_router(public.router, prefix="/v1/public", tags=["public"])
app.include_router(github_integration.router, prefix="/v1/integrations", tags=["integrations"])
app.include_router(gitlab_integration.router, prefix="/v1/integrations", tags=["integrations"])
