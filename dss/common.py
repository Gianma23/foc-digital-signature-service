import base64
import json
import os
import socket
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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
    # Canonical JSON stable for signatures/transcripts
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
# AEAD session with anti-replay
# -----------------------------
def derive_nonce(base_nonce_12: bytes, seq: int) -> bytes:
    """
    Deterministic nonce = base_nonce XOR seq (on last 8 bytes).
    base_nonce must be 12 bytes.
    """
    if len(base_nonce_12) != 12:
        raise ValueError("base_nonce must be 12 bytes")
    seq_bytes = seq.to_bytes(8, "big")
    prefix = base_nonce_12[:4]
    tail = bytes(a ^ b for a, b in zip(base_nonce_12[4:], seq_bytes))
    return prefix + tail


@dataclass
class ChannelKeys:
    key: bytes        # 32 bytes AES key
    base_nonce: bytes # 12 bytes


class SecureChannel:
    """
    Two-direction secure channel:
      - c2s keys for client->server
      - s2c keys for server->client
    Each direction has independent seq counters.
    """

    def __init__(self, session_id: bytes, c2s: ChannelKeys, s2c: ChannelKeys):
        self.session_id = session_id  # bytes
        self.c2s = c2s
        self.s2c = s2c
        self.c2s_recv_expected = 0
        self.s2c_recv_expected = 0
        self.c2s_send_seq = 0
        self.s2c_send_seq = 0

    def encrypt_c2s(self, inner: dict) -> dict:
        seq = self.c2s_send_seq
        self.c2s_send_seq += 1
        nonce = derive_nonce(self.c2s.base_nonce, seq)
        aad = b"DSS1|C2S|" + self.session_id + seq.to_bytes(8, "big")
        pt = canonical_json(inner)
        ct = AESGCM(self.c2s.key).encrypt(nonce, pt, aad)
        return {"type": "data", "dir": "c2s", "seq": seq, "ct": b64e(ct)}

    def decrypt_c2s(self, outer: dict) -> dict:
        if outer.get("type") != "data" or outer.get("dir") != "c2s":
            raise ValueError("Not a c2s data frame")
        seq = int(outer["seq"])
        if seq != self.c2s_recv_expected:
            raise ValueError(f"Replay/out-of-order (expected {self.c2s_recv_expected}, got {seq})")
        nonce = derive_nonce(self.c2s.base_nonce, seq)
        aad = b"DSS1|C2S|" + self.session_id + seq.to_bytes(8, "big")
        ct = b64d(outer["ct"])
        pt = AESGCM(self.c2s.key).decrypt(nonce, ct, aad)
        self.c2s_recv_expected += 1
        return json.loads(pt.decode("utf-8"))

    def encrypt_s2c(self, inner: dict) -> dict:
        seq = self.s2c_send_seq
        self.s2c_send_seq += 1
        nonce = derive_nonce(self.s2c.base_nonce, seq)
        aad = b"DSS1|S2C|" + self.session_id + seq.to_bytes(8, "big")
        pt = canonical_json(inner)
        ct = AESGCM(self.s2c.key).encrypt(nonce, pt, aad)
        return {"type": "data", "dir": "s2c", "seq": seq, "ct": b64e(ct)}

    def decrypt_s2c(self, outer: dict) -> dict:
        if outer.get("type") != "data" or outer.get("dir") != "s2c":
            raise ValueError("Not a s2c data frame")
        seq = int(outer["seq"])
        if seq != self.s2c_recv_expected:
            raise ValueError(f"Replay/out-of-order (expected {self.s2c_recv_expected}, got {seq})")
        nonce = derive_nonce(self.s2c.base_nonce, seq)
        aad = b"DSS1|S2C|" + self.session_id + seq.to_bytes(8, "big")
        ct = b64d(outer["ct"])
        pt = AESGCM(self.s2c.key).decrypt(nonce, ct, aad)
        self.s2c_recv_expected += 1
        return json.loads(pt.decode("utf-8"))
