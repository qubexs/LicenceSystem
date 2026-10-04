"""Door 1 — Device API. Unauthenticated, rate-limited, generic errors (no enumeration)."""
from __future__ import annotations
import time
import uuid
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from . import db as dbmod
from . import security as sec

router = APIRouter(prefix="/v1/device", tags=["device"])

# Tiny in-memory rate limiter (per-process; Cloudflare WAF is the outer layer).
_HITS: dict[str, list[float]] = {}
def _limited(key: str, limit: int = 10, window: int = 60) -> bool:
    now = time.time()
    arr = [t for t in _HITS.get(key, []) if now - t < window]
    if len(arr) >= limit:
        _HITS[key] = arr
        return True
    arr.append(now)
    _HITS[key] = arr
    return False

GENERIC = {"error": "invalid_request"}  # identical for all device failures


class DeviceRequest(BaseModel):
    device_id: str = Field(min_length=4, max_length=128)
    request_id: str = Field(min_length=4, max_length=128)
    platform: str = Field(default="", max_length=64)
    app_version: str = Field(default="", max_length=32)
    device_label: str = Field(default="", max_length=128)


class Heartbeat(BaseModel):
    device_id: str
    license_jwt: str


class RecoveryValidate(BaseModel):
    device_id: str
    code: str


@router.post("/request")
def device_request(body: DeviceRequest, request: Request):
    if _limited(f"req:{request.client.host if request.client else 'x'}", 10, 60):
        return {"status": "pending"}  # do not signal rate-limit distinctly
    conn = dbmod.get_conn()
    try:
        row = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.device_id,)).fetchone()
        now = dbmod.now_ts()
        if row is None:
            conn.execute(
                "INSERT INTO devices(device_id,request_id,label,platform,app_version,status,first_seen,last_seen) VALUES(?,?,?,?,?,'pending',?,?)",
                (body.device_id, body.request_id, body.device_label, body.platform, body.app_version, now, now),
            )
            conn.commit()
        else:
            conn.execute("UPDATE devices SET last_seen=?, platform=?, app_version=? WHERE device_id=?",
                         (now, body.platform, body.app_version, body.device_id))
            conn.commit()
        return {"status": "pending"}
    finally:
        conn.close()


@router.get("/status")
def device_status(device_id: str, request_id: str):
    """Poll endpoint. Pending -> 202-style body; active -> license JWT."""
    conn = dbmod.get_conn()
    try:
        row = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if row is None or row["request_id"] != request_id:
            return GENERIC  # same shape for unknown (prevents enumeration)
        st = row["status"]
        if st == "active":
            lic = conn.execute("SELECT * FROM licenses WHERE device_id=? AND revoked=0 ORDER BY issued_at DESC LIMIT 1",
                               (device_id,)).fetchone()
            # Re-sign stateless JWT on poll so rotation (kid/lic_ver) propagates.
            token = sec.sign_license(device_id, license_version=row["license_version"], jti=lic["jti"] if lic else None)
            return {"status": "active", "license_jwt": token, "license_version": row["license_version"]}
        if st in ("suspended", "revoked"):
            return {"status": st}
        return {"status": "pending"}
    except Exception:
        return GENERIC
    finally:
        conn.close()


@router.post("/heartbeat")
def heartbeat(body: Heartbeat):
    conn = dbmod.get_conn()
    try:
        try:
            payload = sec.verify_license(body.license_jwt)
        except ValueError:
            return GENERIC
        if payload.get("sub") != body.device_id:
            return GENERIC
        row = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.device_id,)).fetchone()
        if row is None:
            return GENERIC
        conn.execute("UPDATE devices SET last_seen=? WHERE device_id=?", (dbmod.now_ts(), body.device_id))
        conn.commit()
        return {"status": row["status"], "license_version": row["license_version"]}
    finally:
        conn.close()


@router.post("/recovery/validate")
def recovery_validate(body: RecoveryValidate):
    conn = dbmod.get_conn()
    try:
        h = sec.hash_code(body.code.strip().upper())
        row = conn.execute("SELECT * FROM recovery_codes WHERE code_hash=? AND device_id=?",
                           (h, body.device_id)).fetchone()
        if row is None or row["used"]:
            return GENERIC
        if row["expires_at"] < dbmod.now_ts():
            return GENERIC
        conn.execute("UPDATE recovery_codes SET used=1, used_at=? WHERE code_hash=?", (dbmod.now_ts(), h))
        conn.execute("INSERT INTO audit(actor,action,target_device,ip,ts,detail) VALUES(?,?,?,?,?,?)",
                     ("device", "recovery.used", body.device_id, "", dbmod.now_ts(), ""))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@router.get("/public-key")
def public_key():
    """Desktop fetches/verifies key; installer may also embed it. Returns raw PEM."""
    from . import config
    from pathlib import Path
    try:
        return {"kid": config.KEY_ID, "pem": Path(config.PUBLIC_KEY_PATH).read_text()}
    except Exception:
        return GENERIC
