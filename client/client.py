import base64
import os
import socket
from pathlib import Path
import time
from .config import HOST, PORT, SERVER_PUBKEY_PATH, DELTA_TIME
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from shared.common import ChannelKeysCBC, _aes_cbc_encrypt, hmac_sha256

from shared.common import (
    send_frame, recv_frame, canonical_json, b64e, b64d,
    sha256, hkdf_expand, SecureChannel, hmac_verify, _aes_cbc_decrypt
)


def load_server_pubkey() -> rsa.RSAPublicKey:
    if not SERVER_PUBKEY_PATH.exists():
        raise FileNotFoundError(
            f"Missing DSS RSA public key at {SERVER_PUBKEY_PATH}. "
            f"Run server.py once, then distribute this public key to clients (offline)."
        )
    pub = serialization.load_pem_public_key(SERVER_PUBKEY_PATH.read_bytes())
    return pub


def do_handshake(sock: socket.socket, server_pub: rsa.RSAPublicKey) -> SecureChannel:

    # ============== Server authentication with certificate ==============
    client_hello = {
        "type": "hello"
    }
    send_frame(sock, client_hello)
    cert = recv_frame(sock)
    if cert.get("type") != "certS":
        raise ValueError("Expected certS")

    server_pub_pem = b64d(cert["rsa_pub_pem_b64"])
    server_pub = serialization.load_pem_public_key(server_pub_pem)

    pinned_pem = server_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if server_pub_pem != pinned_pem:
        raise ValueError("Server certificate/public key not trusted")
    print("[+] Server certificate verified")

    # ============== ECDHE ==============
    c_eph_priv = x25519.X25519PrivateKey.generate()
    cpub_bytes = c_eph_priv.public_key().public_bytes_raw()
    cpub_msg = {
        "x25519_pub_b64": b64e(cpub_bytes),
    }
    send_frame(sock, cpub_msg)
    print("[+] Sent client ECDHE public key")
    spub_msg = recv_frame(sock)
    if spub_msg.get("type") != "Ysrv":
        raise ValueError("Expected server ECDHE public key")

    sig = b64d(spub_msg["sig_b64"])
    spub_msg.pop("sig_b64", None)

    # verify RSA-PSS(SHA256) over sha256(transcript)
    server_pub.verify(
        sig,
        canonical_json(spub_msg),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    spub = x25519.X25519PublicKey.from_public_bytes(b64d(spub_msg["x25519_pub_b64"]))
    shared = c_eph_priv.exchange(spub)
    print("[+] Computed shared secret with ECDHE")

    # ============== Key Derivation ==============
    msgs_for_transcript = [client_hello, cert, cpub_msg, spub_msg]
    transcript = b"".join(canonical_json(m) for m in msgs_for_transcript)
    salt = sha256(transcript)
    session_id = sha256(b"DSS|SID|" + transcript)[:16]

    AES_key = hkdf_expand(shared, salt=salt, info=b"DSS|AES", length=32)
    HMAC_key = hkdf_expand(shared, salt=salt, info=b"DSS|HMAC", length=32)

    print("[+] Computed session keys with HKDF")
    #TODO: rimuovere chiavi effimere

    # ============== FinishedS ==============
    ch = recv_frame(sock)
    if ch.get("type") != "challenge":
        raise ValueError("Expected challenge")
    ch.pop("type")
    tag = b64d(ch.pop("tag_b64", None))
    if hmac_verify(HMAC_key, canonical_json(ch), tag) is False:
        raise ValueError("Invalid HMAC on challenge")
    
    ct = b64d(ch["ct_b64"])
    iv = b64d(ch["iv_b64"])
    timestamp = ch["timestamp"]

    pt = _aes_cbc_decrypt(AES_key, iv, ct)
    if pt != salt:
        raise ValueError("Invalid challenge response plaintext")
    
    if abs(timestamp - time.time()) > DELTA_TIME:
        raise ValueError("Challenge response timestamp out of range")

    print("[+] Server Finished verified")
    
    # ============== FinishedC ==============
    iv = os.urandom(16)
    timestamp = time.time()
    ct = _aes_cbc_encrypt(AES_key, iv, salt)

    content = canonical_json({
        "ct_b64": b64e(ct),
        "timestamp": timestamp,
        "iv_b64": b64e(iv),
    })
    tag_s = hmac_sha256(HMAC_key, content)

    send_frame(sock, {
        "type": "challenge",
        "ct_b64": b64e(ct),
        "timestamp": timestamp,
        "iv_b64": b64e(iv),
        "tag_b64": b64e(tag_s)
    })

    print("[+] Client Finished verified")
    print("[+] Handshake complete")

    session_id = sha256(b"DSS|SID|" + salt)[:16]
    return SecureChannel(
        session_id=session_id,
        AES_key=AES_key,
        HMAC_key=HMAC_key,
    )
 


def req(ch: SecureChannel, sock: socket.socket, op: str, **kwargs) -> dict:
    inner = {"type": "req", "op": op, **kwargs}
    send_frame(sock, ch.channel_send(inner))
    outer = recv_frame(sock)
    return ch.channel_receive(outer)


def main():
    server_pub = load_server_pubkey()

    username = input("Username: ").strip()
    password = input("Password: ").strip()
    new_password = input("New password (leave empty unless first login): ").strip()
    if new_password == "":
        new_password = None

    with socket.create_connection((HOST, PORT)) as sock:
        ch = do_handshake(sock, server_pub)

        auth_inner = {"type": "auth", "username": username, "password": password}
        if new_password:
            auth_inner["new_password"] = new_password

        send_frame(sock, ch.channel_send(auth_inner))
        auth_resp = ch.channel_receive(recv_frame(sock))
        print("[auth]", auth_resp)
        if not auth_resp.get("ok"):
            raise ValueError("Authentication failed")

        print("Commands: createkeys | deletekeys | getpub <user> | signdoc <path> | quit")
        while True:
            line = input("dss> ").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()

            if cmd == "createkeys":
                print(req(ch, sock, "CreateKeys"))

            elif cmd == "deletekeys":
                print(req(ch, sock, "DeleteKeys"))

            elif cmd == "getpub":
                if len(parts) != 2:
                    print("Usage: getpub <username>")
                    continue
                print(req(ch, sock, "GetPublicKey", target_user=parts[1]))

            elif cmd == "signdoc":
                if len(parts) != 2:
                    print("Usage: signdoc <path>")
                    continue
                p = Path(parts[1])
                data = p.read_bytes()
                doc_b64 = base64.b64encode(data).decode("ascii")
                print(req(ch, sock, "SignDoc", doc_b64=doc_b64))

            elif cmd == "quit":
                print(req(ch, sock, "Quit"))
                break
            else:
                print("Unknown command")


if __name__ == "__main__":
    main()
