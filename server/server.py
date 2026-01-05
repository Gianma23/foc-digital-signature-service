import json
import os
import socket
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shared.common import ChannelKeysCBC

from shared.common import (
    send_frame, recv_frame, canonical_json, b64e, b64d,
    sha256, hkdf_expand, SecureChannel, ChannelKeys,
    verify_password, hash_password
)

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "server_data"
KEYS_DIR = DATA_DIR / "keys"
DB_PATH = DATA_DIR / "users.json"

HOST = "127.0.0.1"
PORT = 5050

RSA_KEY_SIZE = 2048  # puoi mettere 3072 se vuoi


def ensure_dirs():
    DATA_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(exist_ok=True)


# -----------------------------
# Persistent server RSA signing keys (DSS)
# -----------------------------
def load_or_create_server_signing_key() -> rsa.RSAPrivateKey:
    priv_path = KEYS_DIR / "dss_rsa_private.pem"
    pub_path = KEYS_DIR / "dss_rsa_public.pem"

    if priv_path.exists() and pub_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        return priv

    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    pub = priv.public_key()

    priv_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"[server] Created DSS RSA signing keypair in {KEYS_DIR}")
    print(f"[server] Distribute public key to users offline: {pub_path}")
    return priv


def load_or_create_master_key() -> bytes:
    mk_path = KEYS_DIR / "master_key.bin"
    env = os.environ.get("DSS_MASTER_KEY_B64")
    if env:
        import base64
        return base64.b64decode(env.encode("ascii"))

    if mk_path.exists():
        return mk_path.read_bytes()

    mk = os.urandom(32)
    mk_path.write_bytes(mk)
    print(f"[server] Created master key in {mk_path} (keep it secret!)")
    return mk


# -----------------------------
# DB helpers
# -----------------------------
def load_db() -> dict:
    if not DB_PATH.exists():
        return {"users": {}}
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def save_db(db: dict) -> None:
    DB_PATH.write_text(json.dumps(db, indent=2, sort_keys=True), encoding="utf-8")


def get_user(db: dict, username: str) -> dict | None:
    return db["users"].get(username)


# -----------------------------
# Key-at-rest encryption
# -----------------------------
def user_wrap_key(master_key: bytes, username: str) -> bytes:
    salt = sha256(username.encode("utf-8"))
    return hkdf_expand(master_key, salt=salt, info=b"DSS|USERKEYWRAP", length=32)


def encrypt_at_rest(master_key: bytes, username: str, plaintext: bytes) -> tuple[bytes, bytes]:
    k = user_wrap_key(master_key, username)
    nonce = os.urandom(12)
    ct = AESGCM(k).encrypt(nonce, plaintext, b"DSS|ATREST|" + username.encode("utf-8"))
    return nonce, ct


def decrypt_at_rest(master_key: bytes, username: str, nonce: bytes, ciphertext: bytes) -> bytes:
    k = user_wrap_key(master_key, username)
    return AESGCM(k).decrypt(nonce, ciphertext, b"DSS|ATREST|" + username.encode("utf-8"))


# -----------------------------
# DSS operations (RSA user keys)
# -----------------------------
def op_create_keys(db: dict, master_key: bytes, username: str) -> dict:
    u = get_user(db, username)
    if not u or not u.get("active", False):
        return {"ok": False, "err": "User not registered/active"}
    if u.get("blocked_after_delete", False):
        return {"ok": False, "err": "Keys were deleted; user must be offline re-registered"}

    if u.get("user_keys"):
        return {"ok": True, "msg": "Keypair already exists (no-op)"}

    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    nonce, ct = encrypt_at_rest(master_key, username, priv_bytes)

    u["user_keys"] = {
        "pub_pem_b64": b64e(pub_bytes),
        "priv_nonce_b64": b64e(nonce),
        "priv_ct_b64": b64e(ct),
        "alg": f"RSA-{RSA_KEY_SIZE}",
        "sig_scheme": "RSASSA-PSS-SHA256",
    }
    save_db(db)
    return {"ok": True, "msg": "RSA keypair created"}


def op_get_public_key(db: dict, target_user: str) -> dict:
    u = get_user(db, target_user)
    if not u or not u.get("user_keys"):
        return {"ok": False, "err": "No public key for that user"}
    return {
        "ok": True,
        "public_key_pem_b64": u["user_keys"]["pub_pem_b64"],
        "alg": u["user_keys"]["alg"],
        "sig_scheme": u["user_keys"]["sig_scheme"],
    }


def op_sign_doc(db: dict, master_key: bytes, username: str, doc_b64: str) -> dict:
    u = get_user(db, username)
    if not u or not u.get("user_keys"):
        return {"ok": False, "err": "No keypair for invoking user"}

    uk = u["user_keys"]
    nonce = b64d(uk["priv_nonce_b64"])
    ct = b64d(uk["priv_ct_b64"])
    priv_pem = decrypt_at_rest(master_key, username, nonce, ct)

    priv = serialization.load_pem_private_key(priv_pem, password=None)

    doc = b64d(doc_b64)
    sig = priv.sign(
        doc,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return {"ok": True, "signature_b64": b64e(sig), "alg": uk["alg"], "sig_scheme": uk["sig_scheme"]}


def op_delete_keys(db: dict, username: str) -> dict:
    u = get_user(db, username)
    if not u or not u.get("active", False):
        return {"ok": False, "err": "User not registered/active"}

    u.pop("user_keys", None)
    u["blocked_after_delete"] = True
    save_db(db)
    return {"ok": True, "msg": "Keypair deleted; user blocked until offline re-registered"}


# -----------------------------
# Handshake + client handler
# -----------------------------
def do_handshake(sock: socket.socket, dss_priv: rsa.RSAPrivateKey) -> SecureChannel:
    """
    Handshake:
      C->S: ClientHello {crand, cpub}
      S->C: ServerHello {srand, spub, sig(transcript)}
    Signature: RSA-PSS(SHA256) over sha256(transcript)
    """
    client_hello = recv_frame(sock)
    if client_hello.get("type") != "hello":
        raise ValueError("Expected hello")
    
    pub_pem = dss_priv.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    send_frame(sock, {
        "type": "certS",
        "rsa_pub_pem_b64": b64e(pub_pem),
        "sig_scheme": "RSA-PSS-SHA256",
        "dh_group": "RFC3526-group14-2048",
    })
    return None  # Handshake not implemented

    # cpub = x25519.X25519PublicKey.from_public_bytes(b64d(client_hello["x25519_pub_b64"]))
    # s_eph_priv = x25519.X25519PrivateKey.generate()
    # spub_bytes = s_eph_priv.public_key().public_bytes(
    #     encoding=serialization.Encoding.Raw,
    #     format=serialization.PublicFormat.Raw,
    # )

    # server_hello_no_sig = {
    #     "type": "server_hello",
    #     "ver": 1,
    #     "server_random_b64": b64e(os.urandom(32)),
    #     "x25519_pub_b64": b64e(spub_bytes),
    # }

    # transcript = canonical_json(client_hello) + canonical_json(server_hello_no_sig)
    # h = sha256(transcript)

    # sig = dss_priv.sign(
    #     h,
    #     padding.PSS(
    #         mgf=padding.MGF1(hashes.SHA256()),
    #         salt_length=padding.PSS.MAX_LENGTH,
    #     ),
    #     hashes.SHA256(),
    # )

    # server_hello = dict(server_hello_no_sig)
    # server_hello["sig_b64"] = b64e(sig)
    # server_hello["sig_scheme"] = "RSA-PSS-SHA256"
    # send_frame(sock, server_hello)

    # shared = s_eph_priv.exchange(cpub)
    # salt = sha256(transcript)
    # session_id = sha256(b"DSS|SID|" + transcript)[:16]

    # c2s_enc = hkdf_expand(shared, salt=salt, info=b"DSS|C2S|ENC", length=32)
    # c2s_mac = hkdf_expand(shared, salt=salt, info=b"DSS|C2S|MAC", length=32)
    # c2s_iv  = hkdf_expand(shared, salt=salt, info=b"DSS|C2S|IV",  length=16)

    # s2c_enc = hkdf_expand(shared, salt=salt, info=b"DSS|S2C|ENC", length=32)
    # s2c_mac = hkdf_expand(shared, salt=salt, info=b"DSS|S2C|MAC", length=32)
    # s2c_iv  = hkdf_expand(shared, salt=salt, info=b"DSS|S2C|IV",  length=16)

    # return SecureChannel(
    #     session_id=session_id,
    #     c2s=ChannelKeysCBC(enc_key=c2s_enc, mac_key=c2s_mac, base_iv=c2s_iv),
    #     s2c=ChannelKeysCBC(enc_key=s2c_enc, mac_key=s2c_mac, base_iv=s2c_iv),
    # )


def handle_client(conn: socket.socket, addr, dss_priv, master_key):
    try:
        ch = do_handshake(conn, dss_priv)

        outer = recv_frame(conn)
        auth = ch.decrypt_c2s(outer)
        if auth.get("type") != "auth":
            raise ValueError("Expected auth message")

        username = auth.get("username", "")
        password = auth.get("password", "")
        new_password = auth.get("new_password")

        db = load_db()
        u = get_user(db, username)
        if not u or not u.get("active", False):
            send_frame(conn, ch.encrypt_s2c({"type": "auth_resp", "ok": False, "err": "Unknown/inactive user"}))
            return

        salt = b64d(u["pw_salt_b64"])
        pw_hash = b64d(u["pw_hash_b64"])
        if not verify_password(password, salt, pw_hash):
            send_frame(conn, ch.encrypt_s2c({"type": "auth_resp", "ok": False, "err": "Bad credentials"}))
            return

        if u.get("first_login", False):
            if not new_password:
                send_frame(conn, ch.encrypt_s2c({"type": "auth_resp", "ok": False, "err": "Password must be changed at first login"}))
                return
            nsalt, nhash = hash_password(new_password)
            u["pw_salt_b64"] = b64e(nsalt)
            u["pw_hash_b64"] = b64e(nhash)
            u["first_login"] = False
            save_db(db)

        send_frame(conn, ch.encrypt_s2c({"type": "auth_resp", "ok": True, "msg": "Authenticated"}))

        while True:
            outer = recv_frame(conn)
            req = ch.decrypt_c2s(outer)
            if req.get("type") != "req":
                raise ValueError("Expected req")

            op = req.get("op")
            if op == "Ping":
                resp = {"ok": True, "pong": True}

            elif op == "CreateKeys":
                db = load_db()
                resp = op_create_keys(db, master_key, username)

            elif op == "GetPublicKey":
                db = load_db()
                target = req.get("target_user", "")
                resp = op_get_public_key(db, target)

            elif op == "SignDoc":
                db = load_db()
                doc_b64 = req.get("doc_b64", "")
                resp = op_sign_doc(db, master_key, username, doc_b64)

            elif op == "DeleteKeys":
                db = load_db()
                resp = op_delete_keys(db, username)

            elif op == "Quit":
                resp = {"ok": True, "msg": "Bye"}
                send_frame(conn, ch.encrypt_s2c({"type": "resp", "op": op, **resp}))
                break

            else:
                resp = {"ok": False, "err": f"Unknown op: {op}"}

            send_frame(conn, ch.encrypt_s2c({"type": "resp", "op": op, **resp}))

    except Exception as e:
        print(f"[server] client {addr} error: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    ensure_dirs()
    dss_priv = load_or_create_server_signing_key()
    master_key = load_or_create_master_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(50)
        print(f"[server] listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, dss_priv, master_key),
                daemon=True,
            )
            t.start()


if __name__ == "__main__":
    main()
