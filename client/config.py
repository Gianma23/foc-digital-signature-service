from pathlib import Path

HOST = "127.0.0.1"
PORT = 5050
DELTA_TIME = 2 * 60  # 2 minutes in ms
BASE_DIR = Path(__file__).resolve().parent  # .../client
DATA_DIR = BASE_DIR / "client_data"
SERVER_PUBKEY_PATH = DATA_DIR / "keys" / "dss_rsa_public.pem"
PUBKEYS_DIR = DATA_DIR / "pubkeys"
SIGS_DIR = DATA_DIR / "signatures"
DOCS_DIR = DATA_DIR / "docs"