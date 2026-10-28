import pytest

from vulnshop import config, store
from vulnshop.app import create_app

MARKUP = '<i data-probe="vs">x</i>'
CAROL_V2 = "Ub9^wG3oRl5-Ck1xZp7tJa4m"


def login(client, username, password, path="/login"):
    return client.post(path, json={"username": username, "password": password})


def register(client, name="newuser", password="correct-horse-battery"):
    assert client.post("/api/register", json={"username": name, "password": password}).status_code == 201
    return login(client, name, password).get_json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---- safety constraints ------------------------------------------------------

@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "example.com", ""])
def test_non_loopback_host_is_refused(host, monkeypatch):
    monkeypatch.setenv("HOST", host)
    with pytest.raises(SystemExit):
        create_app()


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_loopback_host_binds_127(host):
    assert config.check_host(host) == "127.0.0.1"


def test_foreign_host_header_is_rejected(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/", headers={"Host": "localhost:5050"}).status_code == 200


def test_download_never_leaves_sandbox(client):
    for name in ("../../../../etc/passwd", "/etc/passwd", "../../token.key", "../../../shop.sqlite3"):
        reply = client.get("/download", query_string={"file": name})
        assert b"root:x:0:0:root" not in reply.data
        assert b"HMAC" not in reply.data
    assert client.get("/download", query_string={"file": "a\x00b"}).status_code == 404


def test_fetch_is_loopback_only(client):
    for url in ("http://example.com/", "http://127.0.0.1.evil.test/", "file:///etc/passwd", "ftp://127.0.0.1/"):
        assert client.get("/api/fetch", query_string={"url": url}).status_code == 400


def test_sql_errors_are_generic(client):
    reply = client.get("/api/search", query_string={"q": "'\"("})
    assert reply.status_code == 500 and reply.get_json() == {"error": "internal error"}
    reply = login(client, "a'", "b")
    assert reply.status_code == 500 and reply.get_json() == {"error": "internal error"}


def test_runaway_queries_are_cut_off(client):
    import time

    endless = "x' UNION SELECT 1,2,(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c)--"
    started = time.monotonic()
    assert client.get("/api/search", query_string={"q": endless}).status_code == 500
    assert time.monotonic() - started < 6
    huge = "x' UNION SELECT 1,2,length(zeroblob(900000000))--"
    assert client.get("/api/search", query_string={"q": huge}).status_code == 500


def test_expired_token_is_rejected(client, monkeypatch):
    from vulnshop import tokens

    token = register(client, "shortlived")
    monkeypatch.setattr(tokens, "LIFETIME", -10)
    stale = login(client, "shortlived", "correct-horse-battery").get_json()["token"]
    assert client.get("/api/profile", headers=auth(token)).status_code == 200
    assert client.get("/api/profile", headers=auth(stale)).status_code == 401


def test_injection_cannot_modify_data(client):
    client.get("/api/search", query_string={"q": "x'; DROP TABLE users;--"})
    client.get("/api/search", query_string={"q": "x' UNION SELECT 1,2,3--"})
    assert login(client, "admin", "admin123").status_code == 200


# ---- safe controls reject their counterpart's payload -------------------------

def v2_token(client, user="carol", password=CAROL_V2):
    return login(client, user, password, "/v2/login").get_json()["token"]


def test_s01_search_is_parameterised(client):
    reply = client.get("/api/v2/search", query_string={"q": "zzz' UNION SELECT id, username, password FROM users--"})
    assert reply.get_json() == []
    assert client.oracle() == []


def test_s02_search_page_escapes(client):
    body = client.get("/v2/search", query_string={"q": MARKUP}).get_data(as_text=True)
    assert MARKUP not in body and "&lt;i data-probe" in body


def test_s03_comments_escape(client):
    token = v2_token(client)
    assert client.post("/api/v2/comments", json={"product_id": 2, "body": MARKUP}, headers=auth(token)).status_code == 201
    body = client.get("/v2/product/2").get_data(as_text=True)
    assert MARKUP not in body and "&lt;i data-probe" in body


def test_s04_orders_check_owner_and_token(client):
    token = v2_token(client)
    assert client.get("/api/v2/orders/1", headers=auth(token)).status_code == 404
    assert client.get("/api/v2/orders/3", headers=auth(token)).status_code == 200
    forged = _none_token("alice")
    assert client.get("/api/v2/orders/1", headers=auth(forged)).status_code == 401


def test_s05_admin_requires_admin_role(client):
    assert client.get("/api/v2/admin/users", headers=auth(v2_token(client))).status_code == 403
    assert client.get("/api/v2/admin/users", headers=auth(_none_token("admin"))).status_code == 401
    assert client.get("/api/v2/admin/users", headers=auth(register(client))).status_code == 403
    assert client.get("/api/v2/admin/users", headers=auth(v2_token(client, "admin", "Xr8&mC5wQa2-Fn9zBj4tVk7d"))).status_code == 200


def test_s06_download_confined_to_files(client):
    for name in ("../secret/decoy-passwd.txt", "/etc/passwd", "..%2fsecret%2fdecoy-passwd.txt"):
        assert client.get("/v2/download", query_string={"file": name}).status_code == 404
    assert client.get("/v2/download", query_string={"file": "readme.txt"}).status_code == 200


@pytest.mark.parametrize("target", ["http://example.invalid/", "//example.invalid/", "/\\example.invalid", "javascript:alert(1)"])
def test_s07_redirect_allowlist(client, target):
    reply = client.get("/v2/redirect", query_string={"next": target})
    assert reply.headers["Location"] == "/"


def test_s08_login_is_hardened(client):
    assert login(client, "admin'--", "x", "/v2/login").status_code == 401
    assert login(client, "admin", "admin123", "/v2/login").status_code == 401
    assert login(client, "carol", CAROL_V2, "/v2/login").status_code == 200
    assert client.oracle() == []


# ---- planted weaknesses fire their oracle exactly once --------------------------

def test_v01_and_v12_are_logged(client):
    assert login(client, "admin'--", "x").status_code == 200
    assert login(client, "admin", "admin123").status_code == 200
    assert login(client, "alice", "wrong").status_code == 401
    assert [e["id"] for e in client.oracle()] == ["V01", "V12"]


def test_oracle_masks_passwords(client):
    login(client, "admin", "admin123")
    assert "admin123" not in config.ORACLE_PATH.read_text()


def test_v07_mass_assignment_logged(client):
    token = register(client)
    assert client.put("/api/profile", json={"role": "admin"}, headers=auth(token)).status_code == 200
    assert [e["id"] for e in client.oracle()] == ["V07"]


def test_v08_only_applies_to_v1(client):
    assert client.get("/api/admin/users", headers=auth(_none_token("admin"))).status_code == 200
    assert [e["id"] for e in client.oracle()] == ["V08"]


def test_v13_trace_only_on_products(client):
    assert b"Traceback" in client.get("/api/products/abc").data
    assert client.get("/nope").get_json() == {"error": "Not Found"}
    assert [e["id"] for e in client.oracle()] == ["V13"]


def test_flags_are_fixed_and_distinct():
    flags = {store.flag(f"V{n:02d}") for n in range(1, 14)}
    assert len(flags) == 13
    assert store.flag("V01") == store.flag("V01")


def _none_token(sub):
    import base64
    import json

    def enc(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{enc({'alg': 'none'})}.{enc({'sub': sub, 'uid': 1, 'role': 'admin'})}."
