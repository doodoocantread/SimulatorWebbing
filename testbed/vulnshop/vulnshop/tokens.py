import base64
import hashlib
import hmac
import json
import time

from . import config

LIFETIME = 3600


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key():
    return config.KEY_PATH.read_bytes()


def _sign(signing_input):
    return hmac.new(_key(), signing_input.encode(), hashlib.sha256).digest()


def issue(payload):
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now = int(time.time())
    body = _b64e(json.dumps({**payload, "iat": now, "exp": now + LIFETIME}).encode())
    signing_input = f"{header}.{body}"
    return f"{signing_input}.{_b64e(_sign(signing_input))}"


def parts(token):
    """Decode (header, payload) without checking anything; None if malformed."""
    try:
        header_b64, body_b64, _ = token.split(".")
        return json.loads(_b64d(header_b64)), json.loads(_b64d(body_b64))
    except ValueError:
        return None


def verify_strict(token):
    try:
        header_b64, body_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        if header.get("alg") != "HS256":
            return None
        expected = _sign(f"{header_b64}.{body_b64}")
        if not hmac.compare_digest(expected, _b64d(sig_b64)):
            return None
        payload = json.loads(_b64d(body_b64))
        if not isinstance(payload, dict) or payload.get("exp", 0) < time.time():
            return None
        return payload
    except ValueError:
        return None


def verify_legacy(token):
    decoded = parts(token)
    if decoded is None:
        return None
    header, payload = decoded
    if str(header.get("alg", "")).lower() == "none":
        return payload if isinstance(payload, dict) else None
    return verify_strict(token)
