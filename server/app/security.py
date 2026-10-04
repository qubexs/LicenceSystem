"""Crypto + auth helpers. Private key never leaves server. Desktop verifies with public key only."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import pyotp

from . import config


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_private_key():
    data = Path(config.PRIVATE_KEY_PATH).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key():
    data = Path(config.PUBLIC_KEY_PATH).read_bytes()
    return serialization.load_pem_public_key(data)


def sign_license(device_id: str, license_version: int = 1, jti: str | None = None) -> str:
    """Perpetual Ed25519 JWT: header.kid + {iss, sub, jti, lic_ver, perpetual, iat}."""
    priv = load_private_key()
    header = {"alg": "EdDSA", "typ": "JWT", "kid": config.KEY_ID}
    payload = {
        "iss": config.LICENSE_ISSUER,
        "sub": device_id,
        "jti": jti or uuid.uuid4().hex,
        "lic_ver": license_version,
        "perpetual": True,
        "iat": int(time.time()),
    }
    signing_input = f"{_b64u_encode(json.dumps(header, separators=(',', ':')).encode())}.{_b64u_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    sig = priv.sign(signing_input.encode())
    return f"{signing_input}.{_b64u_encode(sig)}"


def verify_license(token: str) -> dict:
    """Verify with public key. Raises ValueError on any failure (generic to caller)."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        raise ValueError("bad token")
    pub = load_public_key()
    try:
        pub.verify(_b64u_decode(s_b64), f"{h_b64}.{p_b64}".encode())
    except Exception:
        raise ValueError("bad signature")
    payload = json.loads(_b64u_decode(p_b64))
    if not payload.get("perpetual"):
        raise ValueError("not perpetual")
    return payload


# ---- Admin password (PBKDF2, stdlib; Argon2 optional upgrade Phase 2) ----
def hash_admin_password(pw: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 210_000)
    return f"pbkdf2-sha256$210000${salt.hex()}${dk.hex()}"


def verify_admin_password(pw: str, phc: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = phc.split("$")
        iters_i = int(iters)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), iters_i)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ---- Recovery codes: single-use, short expiry, hashed at rest ----
def new_recovery_code(n: int = 8) -> str:
    return "".join(secrets.choice("23456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(n))


def hash_code(code: str) -> str:
    return hashlib.sha256(f"beest-recovery:{code}".encode()).hexdigest()


# ---- Admin sessions (signed cookie, server checks expiry + IP allowlist) ----
def session_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.SESSION_SECRET, salt="beest-admin")


def create_session(username: str) -> str:
    return session_serializer().dumps({"u": username})


def read_session(token: str) -> str | None:
    try:
        data = session_serializer().loads(token, max_age=config.SESSION_MAX_AGE)
        return str(data.get("u", ""))
    except (BadSignature, SignatureExpired, Exception):
        return None


def verify_totp(code: str) -> bool:
    """True if MFA passes. MFA disabled entirely when no seed is configured."""
    if not config.TOTP_ENABLED:
        return True
    if not code:
        return False
    return pyotp.TOTP(config.ADMIN_TOTP_SEED).verify(code.strip(), valid_window=1)
