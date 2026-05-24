from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.routes import accounts, findings, auth, auth_oauth, settings as settings_router

settings = get_settings()

app = FastAPI(title="Vigil API", version="0.1.0")

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
