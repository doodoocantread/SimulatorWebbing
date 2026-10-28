import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "shop.sqlite3"
ORACLE_PATH = DATA_DIR / "oracle.jsonl"
KEY_PATH = DATA_DIR / "token.key"
SANDBOX_DIR = DATA_DIR / "sandbox"

# Fixed after check_host(); never taken from the environment.
BIND_ADDRESS = "127.0.0.1"
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})

DEFAULT_PORT = 5050


def check_host(value=None):
    """Exit unless HOST (or the given value) names the loopback interface."""
    host = os.environ.get("HOST", BIND_ADDRESS) if value is None else value
    if host not in ALLOWED_HOSTS:
        sys.exit(f"refusing to start: HOST={host!r} is not loopback (127.0.0.1/localhost)")
    return BIND_ADDRESS


def get_port():
    raw = os.environ.get("PORT", str(DEFAULT_PORT))
    try:
        port = int(raw)
    except ValueError:
        sys.exit(f"refusing to start: PORT={raw!r} is not an integer")
    if not 1024 <= port <= 65534:
        sys.exit("refusing to start: PORT must be in 1024..65534 (PORT+1 is used too)")
    return port
