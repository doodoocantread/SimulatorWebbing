"""Answer-key checks for benchmark/targets/vulnshop.toml.

Written for SafetyWebbing (tests/ next to benchmark/). It parses the file with tomllib so it also runs
here; once copied over, add a test that passes the same file to the real `load_manifest`.
"""
import re
import tomllib
from pathlib import Path

import pytest

KEY = Path(__file__).resolve().parents[1] / "benchmark" / "targets" / "vulnshop.toml"

VULN_IDS = {
    "vs-sqli-login", "vs-sqli-search-union", "vs-xss-reflected", "vs-xss-stored-comment",
    "vs-bac-order-idor", "vs-bac-admin-users", "vs-bac-mass-assignment", "vs-auth-token-none",
    "vs-path-traversal-download", "vs-ssrf-fetch", "vs-open-redirect", "vs-auth-default-admin",
    "vs-info-stack-trace", "vs-crypto-md5",
}
SAFE_IDS = {
    "vs-safe-search-api", "vs-safe-search-page", "vs-safe-comments", "vs-safe-orders",
    "vs-safe-admin-users", "vs-safe-download", "vs-safe-redirect", "vs-safe-login",
}
SCAN_TYPES = {"sqli", "xss", "auth", "general"}


@pytest.fixture(scope="module")
def key():
    return tomllib.loads(KEY.read_text(encoding="utf-8"))


def vulnerable(key):
    return [e for e in key["vuln"] if e.get("expect") != "safe"]


def test_target_and_config(key):
    assert key["target"] == "vulnshop"
    assert key["config"] == "default"


def test_counts_match_header(key):
    header = key["expected"]
    entries = vulnerable(key)
    out_of_capability = [e for e in entries if e.get("scoring") == "out_of_capability"]
    safe = [e for e in key["vuln"] if e.get("expect") == "safe"]
    assert len(entries) == header["vulnerable"] == 14
    assert len(entries) - len(out_of_capability) == header["scored"] == 13
    assert len(out_of_capability) == header["out_of_capability"] == 1
    assert len(safe) == header["safe"] == 8
    assert len(key["accepted_weakness"]) == header["accepted_weakness"]


def test_ids_match_verification_script(key):
    assert {e["id"] for e in vulnerable(key)} == VULN_IDS
    assert {e["id"] for e in key["vuln"] if e.get("expect") == "safe"} == SAFE_IDS
    ids = [e["id"] for e in key["vuln"]]
    assert len(ids) == len(set(ids))


def test_scan_types_valid(key):
    for entry in vulnerable(key):
        assert entry["scan_type"] in SCAN_TYPES, entry["id"]


def test_scored_entries_have_file_oracle_and_trace_match(key):
    for entry in vulnerable(key):
        if entry.get("scoring") == "out_of_capability":
            continue
        kinds = [o["kind"] for o in entry["oracles"]]
        assert "file_oracle" in kinds, entry["id"]
        assert "trace_match" in kinds, entry["id"]
        keys = [o["key"] for o in entry["oracles"] if o["kind"] == "file_oracle"]
        assert all(re.fullmatch(r"V(0[1-9]|1[0-3])", k) for k in keys), entry["id"]


def test_out_of_capability_entry_has_no_oracle(key):
    (entry,) = [e for e in vulnerable(key) if e.get("scoring") == "out_of_capability"]
    assert entry["id"] == "vs-crypto-md5"
    assert "oracles" not in entry


def test_file_oracle_keys_unique(key):
    keys = [o["key"] for e in key["vuln"] for o in e.get("oracles", []) if o["kind"] == "file_oracle"]
    assert len(keys) == len(set(keys)) == 13


def test_every_regex_compiles(key):
    for entry in key["vuln"]:
        for oracle in entry.get("oracles", []):
            for name, value in oracle.items():
                if name.endswith("pattern"):
                    re.compile(value)


def test_safe_entries_have_endpoints_only(key):
    for entry in key["vuln"]:
        if entry.get("expect") == "safe":
            assert entry["endpoints"]
            assert "oracles" not in entry


def test_accepted_weaknesses_well_formed(key):
    ids = [a["id"] for a in key["accepted_weakness"]]
    assert len(ids) == len(set(ids))
    for weakness in key["accepted_weakness"]:
        assert weakness["reason"].strip()
