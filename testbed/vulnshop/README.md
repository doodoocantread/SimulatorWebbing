# VulnShop

> **This application is intentionally vulnerable. Run it on loopback only. Never deploy it or expose it to a network.**
> *Ứng dụng này cố ý có lỗ hổng, chỉ dùng để kiểm thử cục bộ, không triển khai.*

A simulated web shop (Flask + SQLite) used as a test target with exact ground truth for SafetyWebbing,
and as practice material for code review. Full design: [`docs/vulnshop-plan.md`](../../docs/vulnshop-plan.md).

| | |
|---|---|
| Intentional vulnerabilities | 14 (13 exploitable over HTTP + 1 visible only in code) |
| Safe controls (patched twins) | 8 |
| Accepted weaknesses (`accepted_weakness`) | 8 |
| Everything else | must contain no exploitable vulnerability |

## Running

```bash
cd testbed/vulnshop
pip install -r requirements.txt
python -m vulnshop            # http://127.0.0.1:5050, fake internal service on port 5051
```

`PORT` changes the port (both `PORT` and `PORT+1` must be free, otherwise the app refuses to start).
`HOST` only accepts `127.0.0.1` or `localhost`; any other value makes the app exit with an error, and there
is no flag to disable this.

`python reset.py` rebuilds all of `data/` (database, token key, sandbox files, `oracle.jsonl`).
`python -m vulnshop` runs it automatically if `data/` does not exist. There is no HTTP endpoint for resetting.

Docker (optional, Linux): the app binds loopback only, so `-p` cannot reach it; use
`docker run --network host vulnshop` instead.

## Verification

```bash
python -m vulnshop &                 # or run it in another terminal
python verify_ground_truth.py        # PASS/FAIL table; exits non-zero if the totals do not match
python -m pytest tests safetywebbing/tests
```

`verify_ground_truth.py` runs one proof of concept per HTTP vulnerability and confirms it against
`data/oracle.jsonl`, statically checks the code-only item, and shows that the payload for each safe control
is rejected without producing an oracle line. It also cross-checks the IDs against the answer key if it
finds one.

## Safety constraints

- Binds `127.0.0.1` only; rejects requests whose `Host` is not `127.0.0.1`/`localhost` (DNS rebinding protection).
- All data is fixed fake data; no API keys, no outbound network calls.
- No shell, `eval`, `exec` or `subprocess`. Writes only inside `testbed/vulnshop/data/` (git-ignored).
- File reads stay inside `data/sandbox/` (a virtual path tree containing only decoy files). There is no path to
  real system files.
- Queries built by string concatenation run on a **read-only** SQLite connection with time and size limits.
- The "fetch" feature can only call `127.0.0.1`/`localhost`, on **any port**, and does not follow redirects.

**SSRF note:** because any loopback port is allowed, that endpoint can reach other services listening on the
machine's loopback (for example the SafetyWebbing UI). Run VulnShop on a machine with no sensitive services
on loopback.

## Use in blind review tests

The code handed to reviewers should not include `vulnshop/telemetry.py` (the only file that mentions
IDs/flags), `verify_ground_truth.py`, `safetywebbing/` (the answer key) or `docs/vulnshop-plan.md`.
The package name `vulnshop` and the warning banner are deliberate exceptions (requirement A10).
