from pathlib import Path

HOST = "127.0.0.1"
PORT = 5050

BASE_DIR = Path(__file__).resolve().parent  # .../client
PROJECT_ROOT = BASE_DIR.parent              # root del progetto

SERVER_PUBKEY_PATH = PROJECT_ROOT / "client_data" / "keys" / "dss_rsa_public.pem"