# SimulatorWebbing

Test targets and supporting material for benchmarking
[SafetyWebbing](https://github.com/doodoocantread/SafetyWebbing), a web security testing tool.

## Contents

| Path | What it is |
|---|---|
| [`testbed/vulnshop/`](testbed/vulnshop/) | **VulnShop**: an intentionally vulnerable Flask + SQLite shop with exactly 14 known vulnerabilities and 8 hardened controls, so findings can be scored against exact ground truth. |
| [`docs/vulnshop-plan.md`](docs/vulnshop-plan.md) | Design plan for VulnShop (in Vietnamese): vulnerability list, safety constraints, oracle design and delivery steps. |

## Quick start

```bash
cd testbed/vulnshop
pip install -r requirements.txt
python -m vulnshop                 # http://127.0.0.1:5050
python verify_ground_truth.py      # in another terminal: PASS/FAIL table for all 22 items
python -m pytest tests safetywebbing/tests
```

See the [VulnShop README](testbed/vulnshop/README.md) for configuration, safety constraints and Docker usage.

## Safety

VulnShop is **intentionally vulnerable**. It binds `127.0.0.1` only, uses fabricated data, and confines file
access to a decoy sandbox, but its SSRF endpoint can reach any service on the machine's loopback. Run it only on
a machine you control, never deploy it, and never expose it to a network.

## Repository layout

SafetyWebbing owns the benchmark loader and scorer. The answer key (`benchmark/targets/vulnshop.toml`) and its
test are kept as a draft under `testbed/vulnshop/safetywebbing/` until they are copied into that repository.

## License

See [LICENSE](LICENSE).
