# BEEst License & Admin Server

**Live:** `https://beest.cikgututor.com` · Host: own server (`192.168.0.191:8090`, container `beest-license`) · Tunnel: Cloudflare (`lamp-cloudflared`)

Two doors, one server. The desktop app never holds admin credentials or the license-signing private key.

| Door | Who | Endpoints |
|---|---|---|
| Device API (public, rate-limited, generic errors) | Desktop app | `POST /v1/device/request`, `GET /v1/device/status`, `POST /v1/device/heartbeat`, `POST /v1/device/recovery/validate`, `GET /v1/device/public-key` |
| Admin (owner only) | You | Dashboard `/admin` (pending/devices/audit, login + **Log keluar**), API `/v1/admin/*` (login, logout, pending, devices, approve, suspend, resume, revoke, recovery/issue, audit) |
| Health | Tunnel/monitors | `GET /healthz` → `{"ok":true}` |

Admin auth: password (PBKDF2) + optional TOTP (`BEEST_ADMIN_TOTP_SEED` empty = password only), 30-min session cookie, 5-fail lockout (15 min), optional IP allowlist, every sensitive action audited.

## Layout

```
beest-license/
  compose.yml            # beest-license service, 8090:8000 (8884 reserved staging)
  .env                   # REAL secrets — never commit, never copy off-server
  .env.example           # template
  beest-data/            # SQLite beest.db + keys/ (volume; nightly backup)
  server/
    Dockerfile
    requirements-server.txt
    app/                 # main, config, db, security, device_api, admin_api, admin_ui
    scripts/gen_keys.py  # one-time key + credential generator
    scripts/backup.sh    # nightly SQLite backup (cron)
    tests/               # pytest: approval/suspend/recovery flow
```

## First-time setup (already done — reference only)

```bash
cp .env.example .env
# generate Ed25519 keypair + admin hash + TOTP seed + session secret:
docker run --rm -v ./beest-data:/data -w /srv <image> python -c "..."  # or: python3 server/scripts/gen_keys.py
# fill .env, enroll TOTP if used
docker compose -f compose.yml up -d --build
curl http://192.168.0.191:8090/healthz
```

## Cloudflare wiring (dashboard-managed; local `cloudflared/config.yml` is NOT used)

The tunnel runs with `--token`, so ingress lives in the Zero Trust dashboard (remote config), not the local file:

1. Tunnel public hostname: `beest.cikgututor.com` → `http://192.168.0.191:8090` (already present).
2. DNS `CNAME beest` (auto-created with the hostname), proxied. SSL Full Strict + HSTS.
3. Verify: `curl https://beest.cikgututor.com/healthz` → `{"ok":true}`.
4. Optional: Zero Trust Access policy on `/admin*` as a second gate.

> The container must bind a LAN-reachable port (`8090:8000`, not `127.0.0.1:8090`) or the tunnel gets 502.

## Owner workflows

* **Approve:** device first-run → shows as `pending` in `/admin` → Approve with label → device activates on next poll.
* **Lock:** Suspend (temporary, reversible) / Revoke (permanent, cached and enforced offline).
* **Recovery:** device detail → issue code (shown once in `docker logs beest-license`, 15-min TTL, single-use) → user enters it in the desktop recovery dialog → local PIN reset. PINs never touch the server.
* **Logout:** **Log keluar** button (dashboard) or `POST /v1/admin/logout`. Sessions expire after 30 min idle.

## Desktop integration (`license_client.py` in the BEEst repo)

* Server URL: env `BEEST_SERVER_URL` → settings `license_server_url` → default `https://beest.cikgututor.com`.
* Embedded Ed25519 **public** key only (`kid k1`); pure-stdlib verifier (no new dependencies).
* Startup gate runs after local PIN login: first run requests + waits for approval; cached `active` works offline up to 7 days; cached `revoked` is a hard lock.
* Heartbeat every 4 h; recovery dialog validates codes online.
* Tests: `tests/test_license_client.py` (crypto interop vs server lib + offline policy).

## Ops

* **Redeploy:** `docker compose -f compose.yml up -d --build && curl http://192.168.0.191:8090/healthz`
* **Logs:** `docker logs beest-license --tail 50` (recovery codes print here once).
* **Backup:** cron `scripts/backup.sh` (SQLite `.backup` → `nextcloud-data/beest-backup`, keeps 14). Private key: offline copy.
* **Tests:** `docker build -f server/Dockerfile -t beest-license:test ./server && docker run --rm -v ./server/tests:/srv/tests -w /srv beest-license:test python -m pytest tests/ -q`
* **Rotation/compromise:** generate new keypair as `k2`, set `BEEST_KEY_ID=k2`, bump device `license_version`, re-approve; revoke + reissue affected devices.

## Security notes

* Secrets live only in `.env` and `beest-data/keys/` — never in Git, never in the desktop app.
* Sessions are stateless signed cookies: logout clears the browser cookie; a copied token remains valid until its 30-min expiry by design.
* Device API returns identical generic errors for unknown devices (no enumeration).
