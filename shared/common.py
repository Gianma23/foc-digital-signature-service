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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.constant_time import bytes_eq


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
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    pw_hash = kdf.derive(password.encode("utf-8"))
    return salt, pw_hash


def verify_password(password: str, salt: bytes, pw_hash: bytes) -> bool:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
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


def derive_iv(base_iv_16: bytes, seq: int) -> bytes:
    """
    Deterministic IV = base_iv XOR seq (on last 8 bytes).
    base_iv must be 16 bytes.
    """
    if len(base_iv_16) != 16:
        raise ValueError("base_iv must be 16 bytes")
    seq_bytes = seq.to_bytes(8, "big")
    prefix = base_iv_16[:8]
    tail = bytes(a ^ b for a, b in zip(base_iv_16[8:], seq_bytes))
    return prefix + tail


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


@dataclass
class ChannelKeysCBC:
    enc_key: bytes   # 32 bytes AES-256 key
    mac_key: bytes   # 32 bytes HMAC key
    base_iv: bytes   # 16 bytes


class SecureChannel:
    """
    Two-direction secure channel using:
      - AES-CBC for encryption
      - HMAC-SHA256 for integrity/auth (Encrypt-then-MAC)
      - seq counters for anti-replay/out-of-order

    Outer frame format:
      {type:"data", dir:"c2s"/"s2c", seq:int, iv_b64:str, ct_b64:str, tag_b64:str}
    """

    def __init__(self, session_id: bytes, c2s: ChannelKeysCBC, s2c: ChannelKeysCBC):
        self.session_id = session_id
        self.c2s = c2s
        self.s2c = s2c
        self.c2s_recv_expected = 0
        self.s2c_recv_expected = 0
        self.c2s_send_seq = 0
        self.s2c_send_seq = 0

    def _make_mac_input(self, direction: bytes, seq: int, iv: bytes, ct: bytes) -> bytes:
        # Bind MAC to direction, session, and seq (prevents replay/cross-protocol)
        return b"DSS1|" + direction + b"|" + self.session_id + seq.to_bytes(8, "big") + iv + ct

    # ---------- C2S ----------
    def encrypt_c2s(self, inner: dict) -> dict:
        seq = self.c2s_send_seq
        self.c2s_send_seq += 1

        iv = derive_iv(self.c2s.base_iv, seq)
        pt = canonical_json(inner)
        ct = _aes_cbc_encrypt(self.c2s.enc_key, iv, pt)

        mac_in = self._make_mac_input(b"C2S", seq, iv, ct)
        tag = hmac_sha256(self.c2s.mac_key, mac_in)

        return {
            "type": "data",
            "dir": "c2s",
            "seq": seq,
            "iv_b64": b64e(iv),
            "ct_b64": b64e(ct),
            "tag_b64": b64e(tag),
        }

    def decrypt_c2s(self, outer: dict) -> dict:
        if outer.get("type") != "data" or outer.get("dir") != "c2s":
            raise ValueError("Not a c2s data frame")

        seq = int(outer["seq"])
        if seq != self.c2s_recv_expected:
            raise ValueError(f"Replay/out-of-order (expected {self.c2s_recv_expected}, got {seq})")

        iv = b64d(outer["iv_b64"])
        ct = b64d(outer["ct_b64"])
        tag = b64d(outer["tag_b64"])

        # Recompute tag before decrypt (EtM)
        mac_in = self._make_mac_input(b"C2S", seq, iv, ct)
        exp = hmac_sha256(self.c2s.mac_key, mac_in)
        if not bytes_eq(tag, exp):
            raise ValueError("Bad MAC")

        pt = _aes_cbc_decrypt(self.c2s.enc_key, iv, ct)
        self.c2s_recv_expected += 1
        return json.loads(pt.decode("utf-8"))

    # ---------- S2C ----------
    def encrypt_s2c(self, inner: dict) -> dict:
        seq = self.s2c_send_seq
        self.s2c_send_seq += 1

        iv = derive_iv(self.s2c.base_iv, seq)
        pt = canonical_json(inner)
        ct = _aes_cbc_encrypt(self.s2c.enc_key, iv, pt)

        mac_in = self._make_mac_input(b"S2C", seq, iv, ct)
        tag = hmac_sha256(self.s2c.mac_key, mac_in)

        return {
            "type": "data",
            "dir": "s2c",
            "seq": seq,
            "iv_b64": b64e(iv),
            "ct_b64": b64e(ct),
            "tag_b64": b64e(tag),
        }

    def decrypt_s2c(self, outer: dict) -> dict:
        if outer.get("type") != "data" or outer.get("dir") != "s2c":
            raise ValueError("Not a s2c data frame")

        seq = int(outer["seq"])
        if seq != self.s2c_recv_expected:
            raise ValueError(f"Replay/out-of-order (expected {self.s2c_recv_expected}, got {seq})")

        iv = b64d(outer["iv_b64"])
        ct = b64d(outer["ct_b64"])
        tag = b64d(outer["tag_b64"])

        mac_in = self._make_mac_input(b"S2C", seq, iv, ct)
        exp = hmac_sha256(self.s2c.mac_key, mac_in)
        if not bytes_eq(tag, exp):
            raise ValueError("Bad MAC")

        pt = _aes_cbc_decrypt(self.s2c.enc_key, iv, ct)
        self.s2c_recv_expected += 1
        return json.loads(pt.decode("utf-8"))
