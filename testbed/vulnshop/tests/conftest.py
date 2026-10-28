import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnshop import config, store  # noqa: E402
from vulnshop.app import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setattr(config, "DATA_DIR", data)
    monkeypatch.setattr(config, "DB_PATH", data / "shop.sqlite3")
    monkeypatch.setattr(config, "ORACLE_PATH", data / "oracle.jsonl")
    monkeypatch.setattr(config, "KEY_PATH", data / "token.key")
    monkeypatch.setattr(config, "SANDBOX_DIR", data / "sandbox")
    monkeypatch.delenv("HOST", raising=False)
    store.reset()
    app = create_app()
    app.testing = False  # keep the production error handlers
    test_client = app.test_client()
    test_client.oracle = lambda: [
        json.loads(line) for line in config.ORACLE_PATH.read_text().splitlines() if line
    ]
    return test_client
