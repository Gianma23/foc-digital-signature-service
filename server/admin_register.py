import os
import secrets
import json
from pathlib import Path

from common import hash_password, b64e

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "server_data"
DB_PATH = DATA_DIR / "users.json"

def load_db() -> dict:
    if not DB_PATH.exists():
        return {"users": {}}
    return json.loads(DB_PATH.read_text(encoding="utf-8"))

def save_db(db: dict) -> None:
    DB_PATH.parent.mkdir(exist_ok=True)
    DB_PATH.write_text(json.dumps(db, indent=2, sort_keys=True), encoding="utf-8")

def register_user(username: str, temp_password: str | None = None):
    db = load_db()
    if username in db["users"]:
        print("User exists: updating registration flags (re-register).")

    if temp_password is None:
        temp_password = secrets.token_urlsafe(12)

    salt, pw_hash = hash_password(temp_password)

    db["users"][username] = {
        "active": True,
        "first_login": True,
        "blocked_after_delete": False,
        "pw_salt_b64": b64e(salt),
        "pw_hash_b64": b64e(pw_hash),
        # "user_keys": ... created later
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
