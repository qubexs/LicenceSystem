"""FastAPI factory: Door 1 /v1/device + Door 2 /v1/admin + /admin UI. HTTPS/HSTS at Cloudflare edge + here."""
from __future__ import annotations
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from . import db as dbmod
from .device_api import router as device_router
from .admin_api import router as admin_router
from .admin_ui import router as ui_router


class HSTS(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp


def create_app() -> FastAPI:
    dbmod.init_db()
    app = FastAPI(title="BEEst License Server", version="0.1.0", docs_url=None, redoc_url=None)
    app.add_middleware(HSTS)
    app.include_router(device_router)
    app.include_router(admin_router)
    app.include_router(ui_router)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"ok": True}

    return app


app = create_app()
