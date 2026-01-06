import base64
import json
import os
import time
import secrets
import socket
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.constant_time import bytes_eq

DELTA_TIME = 2 * 60

# -----------------------------
# Framing: 4-byte length + JSON
# -----------------------------
def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf


def send_frame(sock: socket.socket, obj: dict) -> None:
    data = canonical_json(obj)
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_frame(sock: socket.socket) -> dict:
    (n,) = struct.unpack("!I", _read_exact(sock, 4))
    data = _read_exact(sock, n)
    return json.loads(data.decode("utf-8"))


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# -----------------------------
# Base64 helpers
# -----------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# -----------------------------
# HKDF helpers
# -----------------------------
def hkdf_expand(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(secret)


def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


# -----------------------------
# Password hashing (PBKDF2)
# -----------------------------
def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=2**21,
        ad=None,
        secret=None,
    )
    pw_hash = kdf.derive(password.encode("utf-8"))
    return salt, pw_hash


def verify_password(password: str, salt: bytes, pw_hash: bytes) -> bool:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=2**21,
        ad=None,
        secret=None,
    )
    try:
        kdf.verify(password.encode("utf-8"), pw_hash)
        return True
    except Exception:
        return False


# -----------------------------
# CBC + HMAC helpers
# -----------------------------
def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except Exception:
        return False


class SecureChannel:
    """
    Two-direction secure channel using:
      - AES-CBC for encryption
      - HMAC-SHA256 for integrity/auth (Encrypt-then-MAC)
      - seq counters for anti-replay/out-of-order

    Outer frame format:
      {type:"data", dir:"c2s"/"s2c", seq:int, iv_b64:str, ct_b64:str, tag_b64:str}
    """

    def __init__(self, session_id: bytes, AES_key: bytes, HMAC_key: bytes):
        self.session_id = session_id
        self.AES_key = AES_key
        self.HMAC_key = HMAC_key


    # ---------- C2S ----------
    def channel_send(self, inner: dict) -> dict:
        iv = os.urandom(16)
        timestamp = time.time()
        pt = canonical_json(inner)
        ct = _aes_cbc_encrypt(self.AES_key, iv, pt)

        content = canonical_json({
            "ct_b64": b64e(ct),
            "timestamp": timestamp,
            "iv_b64": b64e(iv),
        })
        tag = hmac_sha256(self.HMAC_key, content)

        return {
            "type": "data",
            "timestamp": timestamp,
            "iv_b64": b64e(iv),
            "ct_b64": b64e(ct),
            "tag_b64": b64e(tag)
        }
    

    def channel_receive(self, outer: dict) -> dict:
        if outer.get("type") != "data":
            raise ValueError("Not a data frame")

        outer.pop("type")
        tag = b64d(outer.pop("tag_b64", None))
        if hmac_verify(self.HMAC_key, canonical_json(outer), tag) is False:
            raise ValueError("Invalid HMAC on challenge")
        
        ct = b64d(outer["ct_b64"])
        iv = b64d(outer["iv_b64"])
        timestamp = outer["timestamp"]

        if abs(timestamp - time.time()) > DELTA_TIME:
            raise ValueError("Challenge response timestamp out of range")
        
        pt = _aes_cbc_decrypt(self.AES_key, iv, ct)
        return json.loads(pt)
