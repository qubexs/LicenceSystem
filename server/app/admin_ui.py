"""Minimal server-rendered admin dashboard (stdlib html, no template engine)."""
from __future__ import annotations
import html
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from . import config, db as dbmod
from . import security as sec
from .admin_api import _client_ip, _ip_allowed, _lockout_check, _lockout_fail, _set_status, SESSION_COOKIE

router = APIRouter(tags=["admin-ui"])


def _me(request: Request) -> str | None:
    return sec.read_session(request.cookies.get(SESSION_COOKIE, ""))


def _login_page(error: str = "") -> str:
    e = f'<p style="color:#b3261e">{html.escape(error)}</p>' if error else ""
    totp_row = ('<input name="totp" placeholder="TOTP 6-digit" inputmode="numeric" required>'
                if config.TOTP_ENABLED else
                '<input name="totp" placeholder="TOTP (disabled)" inputmode="numeric">')
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BEEst Admin — Login</title>
<style>body{{font-family:system-ui,sans-serif;max-width:420px;margin:6vh auto;padding:0 16px}}input{{width:100%;padding:10px;margin:6px 0}}button{{padding:10px 18px}}</style>
</head><body><h2>BEEst — Owner Login</h2>{e}
<form method="post" action="/admin/login">
<input name="username" placeholder="Username" autocomplete="username" required>
<input name="password" type="password" placeholder="Password" autocomplete="current-password" required>
{totp_row}
<button type="submit">Masuk</button></form>
<p><small>Short session · lockout after 5 fails · all logins audited.</small></p></body></html>"""


def _dashboard(user: str, pending, devices, audit) -> str:
    def row_p(d):
        return (f"<tr><td><code>{html.escape(d['device_id'])}</code></td>"
                f"<td><code>{html.escape(d['request_id'])}</code></td>"
                f"<td>{html.escape(d['platform'] or '')} / {html.escape(d['app_version'] or '')}</td>"
                f"<td>{d['first_seen']}</td>"
                f"<td><form style='display:inline' method='post' action='/admin/action'>"
                f"<input type='hidden' name='action' value='approve'>"
                f"<input type='hidden' name='device_id' value='{html.escape(d['device_id'])}'>"
                f"<input name='label' placeholder='label e.g. Office-PC-01' size='18'><button>Approve</button></form></td></tr>")
    def row_d(d):
        did = html.escape(d['device_id'])
        return (f"<tr><td><code>{did}</code></td><td>{html.escape(d['label'] or '')}</td>"
                f"<td>{html.escape(d['status'])}</td><td>{d['license_version']}</td><td>{d['last_seen']}</td><td>"
                + "".join(f"<form style='display:inline' method='post' action='/admin/action'>"
                           f"<input type='hidden' name='device_id' value='{did}'>"
                           f"<input type='hidden' name='action' value='{a}'><button>{a.title()}</button></form>"
                           for a in ("suspend", "resume", "revoke", "recovery")) + "</td></tr>")
    def row_a(a):
        return (f"<tr><td>{a['ts']}</td><td>{html.escape(a['actor'])}</td><td>{html.escape(a['action'])}</td>"
                f"<td><code>{html.escape(a['target_device'] or '')}</code></td><td>{html.escape(a['ip'] or '')}</td></tr>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BEEst Admin Dashboard</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:2vh auto;padding:0 16px}}table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{border:1px solid #ddd;padding:6px 8px;text-align:left}}code{{background:#f5f5f5;padding:1px 5px}}</style>
</head><body><h2>BEEst Admin <small>({html.escape(user)}) · {html.escape(config.PUBLIC_BASE_URL)}</small>
<form style="display:inline" method="post" action="/admin/logout"><button>Log keluar</button></form></h2>
<h2>Pending ({len(pending)})</h2>
<table><tr><th>device_id</th><th>request</th><th>platform/app</th><th>first_seen</th><th>approve</th></tr>
{"".join(map(row_p, pending)) or '<tr><td colspan="5">none</td></tr>'}</table>
<h2>Devices ({len(devices)})</h2>
<table><tr><th>device</th><th>label</th><th>status</th><th>lic_ver</th><th>last_seen</th><th>actions</th></tr>
{"".join(map(row_d, devices))}</table>
<p><small>Recovery codes print once to server log (<code>docker logs beest-license</code>), expire in 15 min, single-use.</small></p>
<h2>Audit (latest {len(audit)})</h2>
<table><tr><th>ts</th><th>actor</th><th>action</th><th>target</th><th>ip</th></tr>
{"".join(map(row_a, audit))}</table></body></html>"""


@router.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/admin", status_code=302)


@router.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request):
    user = _me(request)
    if not user:
        return RedirectResponse("/admin/login", status_code=302)
    conn = dbmod.get_conn()
    try:
        pending = conn.execute("SELECT * FROM devices WHERE status='pending' ORDER BY first_seen DESC").fetchall()
        devices = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 100").fetchall()
        audit = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 50").fetchall()
        return HTMLResponse(_dashboard(user, list(pending), list(devices), list(audit)))
    finally:
        conn.close()


@router.get("/admin/login", response_class=HTMLResponse)
def login_page(request: Request):
    return HTMLResponse(_login_page())


@router.post("/admin/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...), totp: str = Form("")):
    ip = _client_ip(request)
    conn = dbmod.get_conn()
    try:
        try:
            _lockout_check(conn, ip)
        except Exception:
            return HTMLResponse(_login_page("locked out, try later"), status_code=429)
        ok = (username.strip() == config.ADMIN_USERNAME
              and sec.verify_admin_password(password, config.ADMIN_PW_HASH)
              and sec.verify_totp(totp))
        if not ok or not _ip_allowed(ip):
            _lockout_fail(conn, ip)
            dbmod.audit(conn, username, "admin.login.fail", "", ip, "ui")
            conn.commit()
            return HTMLResponse(_login_page("invalid credentials"), status_code=401)
        conn.execute("INSERT INTO admin_lockout(ip,fails,locked_until) VALUES(?,?,?) "
                     "ON CONFLICT(ip) DO UPDATE SET fails=0, locked_until=0", (ip, 0, 0))
        dbmod.audit(conn, username, "admin.login.ok", "", ip, "ui")
        conn.commit()
        resp = RedirectResponse("/admin", status_code=302)
        resp.set_cookie(SESSION_COOKIE, sec.create_session(username.strip()), httponly=True,
                        samesite="lax", secure=config.COOKIE_SECURE, max_age=config.SESSION_MAX_AGE, path="/")
        return resp
    finally:
        conn.close()


@router.post("/admin/logout", include_in_schema=False)
def admin_logout_post(request: Request):
    return _do_logout(request)


@router.get("/admin/logout", include_in_schema=False)
def admin_logout_get(request: Request):
    return _do_logout(request)


def _do_logout(request: Request):
    user = _me(request) or "-"
    conn = dbmod.get_conn()
    try:
        dbmod.audit(conn, user, "admin.logout", "", _client_ip(request), "ui")
        conn.commit()
    finally:
        conn.close()
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.post("/admin/action", include_in_schema=False)
def admin_action(request: Request, action: str = Form(...), device_id: str = Form(...),
                 label: str = Form(""), reason: str = Form("")):
    import uuid
    user = _me(request)
    if not user:
        return RedirectResponse("/admin/login", status_code=302)
    conn = dbmod.get_conn()
    try:
        if action == "approve":
            row = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if row:
                jti = uuid.uuid4().hex
                conn.execute("INSERT INTO licenses(jti,device_id,issued_at,license_version,perpetual,revoked) VALUES(?,?,?,?,1,0)",
                             (jti, device_id, dbmod.now_ts(), row["license_version"]))
                _set_status(conn, device_id, "active")
                if label:
                    conn.execute("UPDATE devices SET label=? WHERE device_id=?", (label, device_id))
                dbmod.audit(conn, user, "device.approve", device_id, _client_ip(request), label)
        elif action in ("suspend", "resume", "revoke"):
            target = {"suspend": "suspended", "resume": "active", "revoke": "revoked"}[action]
            _set_status(conn, device_id, target)
            dbmod.audit(conn, user, f"device.{action}", device_id, _client_ip(request), reason)
        elif action == "recovery":
            code = sec.new_recovery_code()
            conn.execute("INSERT INTO recovery_codes(device_id,code_hash,expires_at,used) VALUES(?,?,?,0)",
                         (device_id, sec.hash_code(code), dbmod.now_ts() + 900))
            dbmod.audit(conn, user, "recovery.issue", device_id, _client_ip(request), "")
            conn.commit()
            print(f"[BEEst] recovery code for {device_id}: {code} (expires 15 min, single-use)", flush=True)
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/admin", status_code=302)
