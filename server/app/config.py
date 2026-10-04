"""Env-only configuration. No secrets in Git. Desktop never sees these."""
from __future__ import annotations
import os
from pathlib import Path

DATA_DIR = Path(os.getenv("BEEST_DATA_DIR", "/data"))
DB_PATH = Path(os.getenv("BEEST_DB_PATH", str(DATA_DIR / "beest.db")))
PRIVATE_KEY_PATH = Path(os.getenv("BEEST_PRIVATE_KEY", str(DATA_DIR / "keys" / "license_ed25519.pem")))
PUBLIC_KEY_PATH = Path(os.getenv("BEEST_PUBLIC_KEY", str(DATA_DIR / "keys" / "license_ed25519.pub")))
KEY_ID = os.getenv("BEEST_KEY_ID", "k1")

ADMIN_USERNAME = os.getenv("BEEST_ADMIN_USER", "owner")
# PHC-style string produced by security.hash_admin_password(); set via env, never commit.
ADMIN_PW_HASH = os.getenv("BEEST_ADMIN_PW_HASH", "")
# Base32 TOTP seed for admin MFA. Empty = MFA disabled (password only).
ADMIN_TOTP_SEED = os.getenv("BEEST_ADMIN_TOTP_SEED", "")
TOTP_ENABLED = bool(ADMIN_TOTP_SEED.strip())
SESSION_SECRET = os.getenv("BEEST_SESSION_SECRET", "change-me-in-env")
SESSION_MAX_AGE = int(os.getenv("BEEST_SESSION_MAX_AGE", "1800"))  # 30 min
# Secure cookie in prod (HTTPS). Tests set BEEST_COOKIE_SECURE=0 (http://testserver).
COOKIE_SECURE = os.getenv("BEEST_COOKIE_SECURE", "1") == "1"

# Comma-separated allowlist, e.g. "203.0.113.10,198.51.100.0/24". Empty = allow all (rely on Cloudflare Access).
ADMIN_IP_ALLOWLIST = [s.strip() for s in os.getenv("BEEST_ADMIN_IP_ALLOWLIST", "").split(",") if s.strip()]

LICENSE_ISSUER = os.getenv("BEEST_LICENSE_ISSUER", "beest.cikgututor.com")
PUBLIC_BASE_URL = os.getenv("BEEST_PUBLIC_URL", "https://beest.cikgututor.com")
