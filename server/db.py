import os
import secrets
import json
from pathlib import Path

from shared.common import hash_password, b64e

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

def get_user(db: dict, username: str) -> dict | None:
    return db["users"].get(username)


def remove_user(db: dict, username: str) -> dict:
    users = db["users"]

    if username not in users:
        return {"ok": False, "err": "User not found"}

    # delete user entry
    del users[username]

    # persist
    save_db(db)
    return {"ok": True, "msg": f"User '{username}' removed"}