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
from app.routes import accounts, findings, auth, auth_oauth, github_integration, gitlab_integration, settings as settings_router
from app.routes import controls, exports

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
    allow_origins=["*"] if settings.APP_ENV == "dev" else [settings.API_PUBLIC_URL],
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


app.add_middleware(SecurityHeadersMiddleware)


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
app.include_router(github_integration.router, prefix="/v1/integrations", tags=["integrations"])
app.include_router(gitlab_integration.router, prefix="/v1/integrations", tags=["integrations"])
