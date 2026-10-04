"""Phase-1 flow test: request -> pending -> approve (API) -> poll active + heartbeat + suspend enforced."""
from __future__ import annotations
import base64
import hashlib
import os
import secrets
import tempfile
from pathlib import Path

tmp = Path(tempfile.mkdtemp())

# ALL env BEFORE any app import (config reads env at import time).
_salt = secrets.token_bytes(16)
_dk = hashlib.pbkdf2_hmac("sha256", b"test-pass-123", _salt, 210_000)
os.environ["BEEST_ADMIN_PW_HASH"] = f"pbkdf2-sha256$210000${_salt.hex()}${_dk.hex()}"
os.environ["BEEST_DATA_DIR"] = str(tmp)
os.environ["BEEST_DB_PATH"] = str(tmp / "t.db")
os.environ["BEEST_ADMIN_USER"] = "owner"
os.environ["BEEST_SESSION_SECRET"] = "test-secret-1234567890"
os.environ["BEEST_COOKIE_SECURE"] = "0"
# Random base32 TOTP seed without importing app/pyotp yet.
_seed_raw = secrets.token_bytes(20)
_seed = base64.b32encode(_seed_raw).decode()
os.environ["BEEST_ADMIN_TOTP_SEED"] = _seed

# Generate throwaway keypair into tmp/keys and point config there
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
priv = ed25519.Ed25519PrivateKey.generate()
(tmp / "keys").mkdir(exist_ok=True)
(tmp / "keys" / "license_ed25519.pem").write_bytes(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
(tmp / "keys" / "license_ed25519.pub").write_bytes(priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
os.environ["BEEST_PRIVATE_KEY"] = str(tmp / "keys" / "license_ed25519.pem")
os.environ["BEEST_PUBLIC_KEY"] = str(tmp / "keys" / "license_ed25519.pub")

import pyotp
from fastapi.testclient import TestClient
from app.main import create_app
client = TestClient(create_app())

def test_flow():
    r = client.post("/v1/device/request", json={"device_id": "dev-1", "request_id": "req-1", "platform": "win", "app_version": "1.0.1"})
    assert r.json()["status"] == "pending"
    # unknown device must NOT enumerate distinctly
    r2 = client.get("/v1/device/status", params={"device_id": "nope", "request_id": "nope"})
    assert r2.json() == {"error": "invalid_request"}
    # admin login + approve
    code = pyotp.TOTP(_seed).now()
    lr = client.post("/v1/admin/login", json={"username": "owner", "password": "test-pass-123", "totp": code})
    assert lr.status_code == 200, lr.text
    ar = client.post("/v1/admin/approve", json={"device_id": "dev-1", "label": "PC-01"})
    assert ar.status_code == 200, ar.text
    jwt = ar.json()["license_jwt"]
    s = client.get("/v1/device/status", params={"device_id": "dev-1", "request_id": "req-1"}).json()
    assert s["status"] == "active" and s["license_jwt"]
    h = client.post("/v1/device/heartbeat", json={"device_id": "dev-1", "license_jwt": jwt}).json()
    assert h["status"] == "active"
    # suspend enforced on next heartbeat
    client.post("/v1/admin/suspend", json={"device_id": "dev-1", "reason": "test"})
    h2 = client.post("/v1/device/heartbeat", json={"device_id": "dev-1", "license_jwt": jwt}).json()
    assert h2["status"] == "suspended"
    # recovery single-use
    rc = client.post("/v1/admin/recovery/issue", json={"device_id": "dev-1"}).json()
    assert rc["ok"] and rc["code"]
    v1 = client.post("/v1/device/recovery/validate", json={"device_id": "dev-1", "code": rc["code"]}).json()
    assert v1 == {"ok": True}
    v2 = client.post("/v1/device/recovery/validate", json={"device_id": "dev-1", "code": rc["code"]}).json()
    assert v2 == {"error": "invalid_request"}
