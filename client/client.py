import base64
import os
import socket
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from common import ChannelKeysCBC

from common import (
    send_frame, recv_frame, canonical_json, b64e, b64d,
    sha256, hkdf_expand, SecureChannel, ChannelKeys
)

HOST = "127.0.0.1"
PORT = 5050

BASE = Path(__file__).resolve().parent
SERVER_PUBKEY_PATH = BASE / "server_data" / "keys" / "dss_rsa_public.pem"


def load_server_pubkey() -> rsa.RSAPublicKey:
    if not SERVER_PUBKEY_PATH.exists():
        raise FileNotFoundError(
            f"Missing DSS RSA public key at {SERVER_PUBKEY_PATH}. "
            f"Run server.py once, then distribute this public key to clients (offline)."
        )
    pub = serialization.load_pem_public_key(SERVER_PUBKEY_PATH.read_bytes())
    return pub


def do_handshake(sock: socket.socket, server_pub: rsa.RSAPublicKey) -> SecureChannel:
    c_eph_priv = x25519.X25519PrivateKey.generate()
    cpub_bytes = c_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    client_hello = {
        "type": "client_hello",
        "ver": 1,
        "client_random_b64": b64e(os.urandom(32)),
        "x25519_pub_b64": b64e(cpub_bytes),
    }
    send_frame(sock, client_hello)

    server_hello = recv_frame(sock)
    if server_hello.get("type") != "server_hello":
        raise ValueError("Expected server_hello")

    sig = b64d(server_hello["sig_b64"])
    server_hello_no_sig = dict(server_hello)
    server_hello_no_sig.pop("sig_b64", None)

    transcript = canonical_json(client_hello) + canonical_json(server_hello_no_sig)
    h = sha256(transcript)

    # verify RSA-PSS(SHA256) over sha256(transcript)
    server_pub.verify(
        sig,
        h,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    spub = x25519.X25519PublicKey.from_public_bytes(b64d(server_hello["x25519_pub_b64"]))
    shared = c_eph_priv.exchange(spub)
    salt = sha256(transcript)
    session_id = sha256(b"DSS|SID|" + transcript)[:16]

    cc2s_enc = hkdf_expand(shared, salt=salt, info=b"DSS|C2S|ENC", length=32)
    c2s_mac = hkdf_expand(shared, salt=salt, info=b"DSS|C2S|MAC", length=32)
    c2s_iv  = hkdf_expand(shared, salt=salt, info=b"DSS|C2S|IV",  length=16)

    s2c_enc = hkdf_expand(shared, salt=salt, info=b"DSS|S2C|ENC", length=32)
    s2c_mac = hkdf_expand(shared, salt=salt, info=b"DSS|S2C|MAC", length=32)
    s2c_iv  = hkdf_expand(shared, salt=salt, info=b"DSS|S2C|IV",  length=16)

    return SecureChannel(
        session_id=session_id,
        c2s=ChannelKeysCBC(enc_key=c2s_enc, mac_key=c2s_mac, base_iv=c2s_iv),
        s2c=ChannelKeysCBC(enc_key=s2c_enc, mac_key=s2c_mac, base_iv=s2c_iv),
    )


def req(ch: SecureChannel, sock: socket.socket, op: str, **kwargs) -> dict:
    inner = {"type": "req", "op": op, **kwargs}
    send_frame(sock, ch.encrypt_c2s(inner))
    outer = recv_frame(sock)
    return ch.decrypt_s2c(outer)


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

        send_frame(sock, ch.encrypt_c2s(auth_inner))
        auth_resp = ch.decrypt_s2c(recv_frame(sock))
        print("[auth]", auth_resp)
        if not auth_resp.get("ok"):
            return

        print("Commands: ping | createkeys | getpub <user> | signdoc <path> | deletekeys | quit")
        while True:
            line = input("dss> ").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()

            if cmd == "ping":
                print(req(ch, sock, "Ping"))

            elif cmd == "createkeys":
                print(req(ch, sock, "CreateKeys"))

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

            elif cmd == "deletekeys":
                print(req(ch, sock, "DeleteKeys"))

            elif cmd == "quit":
                print(req(ch, sock, "Quit"))
                break
            else:
                print("Unknown command")


if __name__ == "__main__":
    main()
