from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.routes import accounts, findings, auth, auth_oauth, settings as settings_router
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.APP_ENV == "dev" else [settings.API_PUBLIC_URL],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
