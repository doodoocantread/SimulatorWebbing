import json
import logging
import re
import time
from urllib.parse import urlsplit

from flask import request

from . import config, store, tokens

_PROTECTED_LEGACY = ("/api/orders", "/api/profile", "/api/admin", "/api/comments")
_FLAG_RESPONSES = {
    "/download": "V09",
    "/api/fetch": "V10",
}
_LOOPBACK = {"127.0.0.1", "localhost"}
log = logging.getLogger(__name__)


def init_app(app):
    app.after_request(_observe)


def _record(vuln_id, extra=None):
    entry = {
        "id": vuln_id,
        "ts": time.time(),
        "flag": store.flag(vuln_id),
        "request": _summary(),
    }
    if extra:
        entry.update(extra)
    with open(config.ORACLE_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def _mask(text):
    return re.sub(r'("?password"?\s*[=:]\s*"?)[^&"\s,}]*', r"\1***", text)


def _summary():
    body = request.get_data(as_text=True)[:300]
    return {
        "method": request.method,
        "path": request.path,
        "query": _mask(request.query_string.decode("utf-8", "replace"))[:300],
        "body": _mask(body),
    }


def _params():
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return request.form


def _principal(conn):
    header = request.headers.get("Authorization", "")
    decoded = tokens.parts(header.removeprefix("Bearer ").strip())
    if decoded is None:
        return None
    sub = decoded[1].get("sub")
    if not isinstance(sub, str):
        return None
    return conn.execute("SELECT * FROM users WHERE username=?", (sub,)).fetchone()


def _observe(response):
    try:
        _inspect(response)
    except Exception:  # telemetry must never break a request
        log.exception("telemetry failed")
    return response


def _inspect(response):
    path, method, status = request.path, request.method, response.status_code
    conn = store.connect_ro()
    try:
        if method == "POST" and path == "/login" and status == 200:
            _check_login(conn)
        if method == "GET" and path == "/api/search" and status == 200:
            body = response.get_data(as_text=True)
            for row in conn.execute("SELECT password FROM users"):
                if row["password"] in body:
                    _record("V02")
                    break
        if method == "GET" and path == "/search" and status == 200:
            q = request.args.get("q", "")
            if "<" in q and q in response.get_data(as_text=True):
                _record("V03")
        if method == "GET" and path.startswith("/product/") and status == 200:
            _check_stored(conn, path, response)
        if method == "GET" and re.fullmatch(r"/api/orders/\d+", path) and status == 200:
            user, order_id = _principal(conn), int(path.rsplit("/", 1)[1])
            order = conn.execute("SELECT user_id FROM orders WHERE id=?", (order_id,)).fetchone()
            if user and order and order["user_id"] != user["id"]:
                _record("V05")
        if method == "GET" and path == "/api/admin/users" and status == 200:
            user = _principal(conn)
            if user and user["role"] != "admin":
                _record("V06")
        if method == "PUT" and path == "/api/profile" and status == 200:
            user = _principal(conn)
            data = request.get_json(silent=True)
            if user and isinstance(data, dict) and data.get("role") == "admin" \
                    and user["role"] == "admin" and user["username"] != "admin":
                _record("V07")
        if path.startswith(_PROTECTED_LEGACY) and status < 400:
            decoded = tokens.parts(request.headers.get("Authorization", "").removeprefix("Bearer ").strip())
            if decoded and str(decoded[0].get("alg", "")).lower() == "none":
                _record("V08")
        marker = _FLAG_RESPONSES.get(path)
        if marker and status == 200 and store.flag(marker) in response.get_data(as_text=True):
            _record(marker)
        if method == "GET" and path == "/redirect" and 300 <= status < 400:
            target = response.headers.get("Location", "")
            parsed = urlsplit(target)
            if target.startswith(("//", "\\\\")) or (parsed.netloc and parsed.hostname not in _LOOPBACK):
                _record("V11")
        if method == "GET" and path.startswith("/api/products/") and status == 500 \
                and "Traceback (most recent call last)" in response.get_data(as_text=True):
            _record("V13")
    finally:
        conn.close()


def _check_login(conn):
    params = _params()
    username, password = str(params.get("username", "")), str(params.get("password", ""))
    legit = conn.execute(
        "SELECT 1 FROM users WHERE username=? AND password=?",
        (username, store.hash_password(password)),
    ).fetchone()
    if not legit:
        _record("V01")
    elif username == "admin" and password == store.DEFAULT_ADMIN_PASSWORD:
        _record("V12")


def _check_stored(conn, path, response):
    product_id = path.rsplit("/", 1)[1]
    if not product_id.isdigit():
        return
    body = response.get_data(as_text=True)
    for row in conn.execute("SELECT body FROM comments WHERE product_id=?", (int(product_id),)):
        if "<" in row["body"] and row["body"] in body:
            _record("V04")
            return
