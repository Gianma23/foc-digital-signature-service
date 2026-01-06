import os
import secrets
import json
from pathlib import Path

from shared.common import hash_password, b64e
from .db import load_db, save_db

def register_user(username: str, temp_password: str | None = None):
    db = load_db()
    if username in db["users"]:
        print("User exists: updating registration flags (re-register).")

    if temp_password is None:
        temp_password = secrets.token_urlsafe(12)

    salt, pw_hash = hash_password(temp_password)

    db["users"][username] = {
        "first_login": True,
        "pw_salt_b64": b64e(salt),
        "pw_hash_b64": b64e(pw_hash),
        # "user_keys": created with CreateKeys
    }
    save_db(db)
    print(f"Registered user '{username}'. Temporary password: {temp_password}")
    print("User must change password at first login.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python admin_register.py <username> [temp_password]")
        raise SystemExit(1)
    username = sys.argv[1]
    pw = sys.argv[2] if len(sys.argv) >= 3 else None
    register_user(username, pw)
