"""Door 2 — Admin API. Session cookie + TOTP + lockout + audit. Same-origin only."""
from __future__ import annotations
import ipaddress
import time
import uuid
from fastapi import APIRouter, Request, Response, HTTPException
from pydantic import BaseModel

from . import config, db as dbmod
from . import security as sec

router = APIRouter(prefix="/v1/admin", tags=["admin"])
SESSION_COOKIE = "beest_admin"


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def _ip_allowed(ip: str) -> bool:
    if not config.ADMIN_IP_ALLOWLIST or not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in config.ADMIN_IP_ALLOWLIST:
        try:
            if "/" in net:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
            elif ip == net:
                return True
        except ValueError:
            continue
    return False


def require_admin(request: Request) -> str:
    token = request.cookies.get(SESSION_COOKIE, "")
    user = sec.read_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    if not _ip_allowed(_client_ip(request)):
        raise HTTPException(status_code=403, detail="ip not allowed")
    return user


def _lockout_check(conn, ip: str):
    row = conn.execute("SELECT * FROM admin_lockout WHERE ip=?", (ip,)).fetchone()
    if row and row["locked_until"] > int(time.time()):
        raise HTTPException(status_code=429, detail="locked out, try later")


def _lockout_fail(conn, ip: str):
    now = int(time.time())
    row = conn.execute("SELECT * FROM admin_lockout WHERE ip=?", (ip,)).fetchone()
    fails = (row["fails"] + 1) if row else 1
    locked_until = now + 900 if fails >= 5 else 0  # 5 fails -> 15 min
    conn.execute("INSERT INTO admin_lockout(ip,fails,locked_until) VALUES(?,?,?) "
                 "ON CONFLICT(ip) DO UPDATE SET fails=excluded.fails, locked_until=excluded.locked_until",
                 (ip, fails, locked_until))
    conn.commit()


class LoginBody(BaseModel):
    username: str
    password: str
    totp: str = ""  # required only when BEEST_ADMIN_TOTP_SEED is set


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    ip = _client_ip(request)
    conn = dbmod.get_conn()
    try:
        _lockout_check(conn, ip)
        if not _ip_allowed(ip):
            raise HTTPException(status_code=403, detail="ip not allowed")
        ok_user = body.username.strip() == config.ADMIN_USERNAME
        ok_pw = sec.verify_admin_password(body.password, config.ADMIN_PW_HASH) if config.ADMIN_PW_HASH else False
        ok_totp = sec.verify_totp(body.totp)
        if not (ok_user and ok_pw and ok_totp):
            _lockout_fail(conn, ip)
            dbmod.audit(conn, body.username, "admin.login.fail", "", ip, "")
            conn.commit()
            raise HTTPException(status_code=401, detail="invalid credentials")
        conn.execute("INSERT INTO admin_lockout(ip,fails,locked_until) VALUES(?,?,?) "
                     "ON CONFLICT(ip) DO UPDATE SET fails=0, locked_until=0", (ip, 0, 0))
        dbmod.audit(conn, body.username, "admin.login.ok", "", ip, "")
        conn.commit()
        response.set_cookie(SESSION_COOKIE, sec.create_session(body.username.strip()),
                            httponly=True, samesite="lax", secure=config.COOKIE_SECURE, max_age=config.SESSION_MAX_AGE, path="/")
        return {"ok": True}
    finally:
        conn.close()


@router.post("/logout")
def logout(response: Response, request: Request):
    user = require_admin(request)
    conn = dbmod.get_conn()
    try:
        dbmod.audit(conn, user, "admin.logout", "", _client_ip(request), "")
        conn.commit()
    finally:
        conn.close()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/pending")
def pending(request: Request):
    user = require_admin(request)
    conn = dbmod.get_conn()
    try:
        rows = conn.execute("SELECT * FROM devices WHERE status='pending' ORDER BY first_seen DESC").fetchall()
        return {"pending": [dict(r) for r in rows], "actor": user}
    finally:
        conn.close()


@router.get("/devices")
def devices(request: Request, q: str = ""):
    require_admin(request)
    conn = dbmod.get_conn()
    try:
        if q:
            rows = conn.execute("SELECT * FROM devices WHERE device_id LIKE ? OR label LIKE ? ORDER BY last_seen DESC",
                                (f"%{q}%", f"%{q}%")).fetchall()
        else:
            rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 500").fetchall()
        return {"devices": [dict(r) for r in rows]}
    finally:
        conn.close()


class TargetBody(BaseModel):
    device_id: str
    label: str = ""
    reason: str = ""
    notes: str = ""


def _set_status(conn, device_id: str, status: str):
    cur = conn.execute("UPDATE devices SET status=?, last_seen=? WHERE device_id=?",
                       (status, dbmod.now_ts(), device_id))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="unknown device")
    if status == "revoked":
        conn.execute("UPDATE licenses SET revoked=1 WHERE device_id=?", (device_id,))


@router.post("/approve")
def approve(body: TargetBody, request: Request):
    user = require_admin(request)
    conn = dbmod.get_conn()
    try:
        row = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.device_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="unknown device")
        jti = uuid.uuid4().hex
        conn.execute("INSERT INTO licenses(jti,device_id,issued_at,license_version,perpetual,revoked) VALUES(?,?,?,?,1,0)",
                     (jti, body.device_id, dbmod.now_ts(), row["license_version"]))
        _set_status(conn, body.device_id, "active")
        if body.label:
            conn.execute("UPDATE devices SET label=? WHERE device_id=?", (body.label, body.device_id))
        dbmod.audit(conn, user, "device.approve", body.device_id, _client_ip(request), body.label)
        conn.commit()
        token = sec.sign_license(body.device_id, license_version=row["license_version"], jti=jti)
        return {"ok": True, "license_jwt": token}
    finally:
        conn.close()


@router.post("/suspend")
def suspend(body: TargetBody, request: Request):
    user = require_admin(request)
    conn = dbmod.get_conn()
    try:
        _set_status(conn, body.device_id, "suspended")
        dbmod.audit(conn, user, "device.suspend", body.device_id, _client_ip(request), body.reason)
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@router.post("/resume")
def resume(body: TargetBody, request: Request):
    user = require_admin(request)
    conn = dbmod.get_conn()
    try:
        _set_status(conn, body.device_id, "active")
        dbmod.audit(conn, user, "device.resume", body.device_id, _client_ip(request), body.reason)
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@router.post("/revoke")
def revoke(body: TargetBody, request: Request):
    user = require_admin(request)
    conn = dbmod.get_conn()
    try:
        _set_status(conn, body.device_id, "revoked")
        dbmod.audit(conn, user, "device.revoke", body.device_id, _client_ip(request), body.reason)
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@router.post("/recovery/issue")
def recovery_issue(body: TargetBody, request: Request):
    """Issue single-use code, 15-min expiry. Plaintext shown ONCE to admin."""
    user = require_admin(request)
    conn = dbmod.get_conn()
    try:
        row = conn.execute("SELECT * FROM devices WHERE device_id=?", (body.device_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="unknown device")
        code = sec.new_recovery_code()
        conn.execute("INSERT INTO recovery_codes(device_id,code_hash,expires_at,used) VALUES(?,?,?,0)",
                     (body.device_id, sec.hash_code(code), dbmod.now_ts() + 900))
        dbmod.audit(conn, user, "recovery.issue", body.device_id, _client_ip(request), "")
        conn.commit()
        return {"ok": True, "code": code, "expires_in_seconds": 900}
    finally:
        conn.close()


@router.get("/audit")
def audit_list(request: Request, limit: int = 200):
    require_admin(request)
    conn = dbmod.get_conn()
    try:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (min(limit, 1000),)).fetchall()
        return {"audit": [dict(r) for r in rows]}
    finally:
        conn.close()
