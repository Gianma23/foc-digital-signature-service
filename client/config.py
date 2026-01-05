from pathlib import Path

HOST = "127.0.0.1"
PORT = 5050
DELTA_TIME = 2 * 60  # 2 minutes in ms
BASE_DIR = Path(__file__).resolve().parent  # .../client
SERVER_PUBKEY_PATH = BASE_DIR / "client_data" / "keys" / "dss_rsa_public.pem"