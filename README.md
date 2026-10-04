# Project 2 — Smart Campus Zero-Trust OT Gateway (Phase 2)

[![CI](https://github.com/toussaintrhyto-web/project-2-zt-ot-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/toussaintrhyto-web/project-2-zt-ot-gateway/actions/workflows/ci.yml)

Phase 2 of the Smart Campus Zero-Trust OT Gateway project: turning the
"Planned Verification" claims on the [design page](../portfolio_demos/project_2.html)
into evidence a reviewer can run — real OPA policy, automated tests in CI, and
(in later workstreams) repeatable device onboarding and packet-level proof of
enforcement.

**Rule for this repo:** the page may only claim what a passing test or a
runnable demo proves. The design page is updated *after* each milestone, never
before (see the claim ladder below).

## Status

| Workstream | Scope | Status |
|---|---|---|
| **A — Policy & tests** | Real Rego v1 policy; `inventory.yaml` as single source of truth; 14 native `opa test` cases + 15 pytest cases against OPA's REST API; CI | ✅ Done — **29 automated tests passing in CI** |
| B — Ansible onboarding | Idempotent device onboarding/offboarding generated from the inventory (OPA data + WireGuard peer + nftables rule) | 🚧 In progress |
| D — Packet-level enforcement | Allowed/denied flows verified at packet level in a Linux lab | ⏳ Planned |

## What is real, what is simulated

- **Real:** the OPA policy and every test in this repo; CI runs them on
  GitHub Actions. Decisions, reasons, and the default-deny behavior are what
  OPA actually computes.
- **Simulated:** the OT devices themselves (BAC0 for BACnet, Mosquitto for
  MQTT) — they stand in for physical controllers and sensors. No cloud
  component exists; everything stays on the campus network.

## Layout

```
inventory/inventory.yaml   # single source of truth: devices + services (identifiers from the design page)
policy/authz.rego          # real policy, Rego v1 (OPA 1.x), data-driven from the inventory
policy/authz_test.rego     # native OPA tests (14 cases)
tests/conftest.py          # starts a real `opa run -s` server, waits for /health
tests/test_policy_decisions.py  # pytest cases against the REST API (15 cases)
scripts/run_opa_tests.sh   # opa test has no --data flag; this assembles the bundle
.github/workflows/ci.yml   # opa check --strict, opa test, pytest (OPA pinned to v1.21.1)
```

## How to run the tests

Prerequisites: **OPA v1.21.1** (pinned — `opa version` should say
`Version: 1.21.1`, `Rego Version: v1`) and **Python 3.10+** with pytest
(`pip install -r requirements.txt`).

```bash
# 1. Policy compiles cleanly in strict mode:
opa check --strict policy/

# 2. Native Rego tests, run against the real inventory (14 cases):
bash scripts/run_opa_tests.sh -v

# 3. Pytest against a real OPA REST server (15 cases):
python -m pytest tests/ -v

# 4. Evaluate a single decision by hand:
opa eval -d policy/ -d inventory/inventory.yaml \
  -i <(echo '{"device_id":"bacnet-controller-hvac-01","dest_ip":"172.16.5.10","dest_port":47808,"protocol":"bacnet-ip"}') \
  'data.campus.ot_gateway' --format raw
```

### Test matrix (Workstream A)

Every allow case has at least one negative control that differs by a single
field, so no test can pass by accident:

| Category | Case | Expected |
|---|---|---|
| Authorized | hvac-01 → bms-plant-controller (ip, port, protocol all match) | allow |
| Authorized | temp-01 → bms-historian (ip, port, protocol all match) | allow |
| Negative control | right device and service, wrong port (×2 devices) | deny |
| Negative control | right device and service, wrong protocol (×2 devices) | deny |
| Unauthorized | active device to a service not in its allowed list | deny |
| Lateral movement | OT device (hvac-02) → another OT segment | deny |
| Lateral movement | OT device → IT-core service (hr-portal) | deny |
| Negative control | unknown device ID | deny |
| Negative control | known device with status revoked / inactive | deny |
| Negative control | empty or malformed input (default deny proven) | deny |

The same matrix is exercised twice: natively (`opa test`) and through the
REST endpoint a real PEP would call (`POST /v1/data/campus/ot_gateway`).
One pytest case additionally proves the design is data-driven: the same
request that is allowed with the real inventory is denied when the device's
status in the inventory is revoked.

## Environment (Session 0 spike)

The enforcement lab runs on **macOS (Apple Silicon) + Docker Desktop**
(LinuxKit kernel `7.0.12-linuxkit`), verified 2026-10-03:

| Capability | Result |
|---|---|
| `nft list ruleset` in a container with `NET_ADMIN` | ✅ works |
| `ip link add wg0 type wireguard` in a container with `NET_ADMIN` | ✅ works (WireGuard kernel support present) |

So the lab uses Linux containers rather than a VM. OPA and pytest run
natively on the Mac; only the enforcement point (PEP) runs in Linux.

## Claim ladder (what this repo proves, and what it does not)

| Evidence | What the design page may say |
|---|---|
| Design only (Phase 1) | "Planned" |
| Rego validated, tests passing in CI (Workstream A — done) | "Policy decisions covered by 29 automated tests, run in CI" |
| Ansible onboarding idempotent (Workstream B) | "Automated, idempotent onboarding in a lab" |
| Packet-level test passing (Workstream D) | "Enforcement verified in a Linux lab" |
| **Never** | "Production-ready", "BACnet/SC bridge", "compliant with NIST 800-207", "eliminates lateral movement" |

Workstream A proves **decisions**, not enforcement: passing OPA tests show
the policy computes the right allow/deny, not that a gateway drops packets.
That upgrade happens in Workstream D.

## Secrets

No keys, vault passwords or `.env` files are committed (see `.gitignore`).
WireGuard public keys are generated at deploy time; any demo keys used in the
lab are throwaway and documented as such.
