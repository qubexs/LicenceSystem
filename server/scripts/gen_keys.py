#!/usr/bin/env python3
"""Generate Ed25519 license keypair + admin password hash + TOTP seed. Run ONCE on server, backup offline."""
from __future__ import annotations
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import pyotp, getpass

from app import security as sec

out = Path("/data/keys") if Path("/data").exists() else Path(__file__).resolve().parents[1] / "keys-out"
out.mkdir(parents=True, exist_ok=True)
priv = ed25519.Ed25519PrivateKey.generate()
pub = priv.public_key()
(out / "license_ed25519.pem").write_bytes(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
(out / "license_ed25519.pub").write_bytes(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
print(f"wrote {out/'license_ed25519.pem'} + .pub  — BACKUP OFFLINE, embed .pub in desktop app")
pw = getpass.getpass("New admin password: ")
print("BEEST_ADMIN_PW_HASH=" + sec.hash_admin_password(pw))
print("BEEST_ADMIN_TOTP_SEED=" + pyotp.random_base32() + "  # scan in authenticator, store in vault")
print("BEEST_SESSION_SECRET=" + sec.new_recovery_code(32))
