"""Shared fixtures for the Phase 2 test suite.

Starts real OPA servers with the policy and inventory loaded exactly as in
production (a bundle of policy/*.rego plus inventory/inventory.yaml as
data.yaml at the data root):

    opa run -s --addr=127.0.0.1:<port> -b <bundle>

Two servers are provided:
  * opa         — the real inventory (session-scoped, shared by all tests)
  * opa_revoked — same inventory with bacnet-controller-hvac-01 revoked,
                  proving through the REST API that decisions are data-driven

Only the Python standard library is used for HTTP, so the only test
dependency is pytest itself.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
OPA_START_TIMEOUT_S = 30


def _opa_bin() -> str:
    opa = shutil.which("opa")
    if opa is None:
        pytest.skip("opa binary not found on PATH (install OPA, see README)")
    return opa


def _assemble_bundle() -> Path:
    """Assemble a temporary OPA bundle, the way production would load it.

    `opa run` (OPA 1.x) has no --data flag; it loads bundles. A bundle
    directory with the policy .rego files plus data.yaml at the root puts
    the inventory at the data root (data.devices / data.services).
    Test files are excluded: a running server should not load them.
    """
    bundle = Path(tempfile.mkdtemp(prefix="opa-bundle-"))
    for rego in sorted((REPO_ROOT / "policy").glob("*.rego")):
        if rego.name.endswith("_test.rego"):
            continue
        shutil.copy(rego, bundle / rego.name)
    shutil.copy(REPO_ROOT / "inventory" / "inventory.yaml", bundle / "data.yaml")
    return bundle


def _inventory_as_json() -> dict:
    """Load the inventory as JSON (OPA does the YAML parsing for us)."""
    out = subprocess.run(
        [
            _opa_bin(), "eval", "-d", str(REPO_ROOT / "inventory" / "inventory.yaml"),
            "data", "--format", "raw",
        ],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(base_url: str, timeout_s: float = OPA_START_TIMEOUT_S) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/health", timeout=1) as resp:
                if resp.status == 200:
                    return
        except Exception as err:  # not up yet; retry until healthy or timeout
            last_err = err
        time.sleep(0.1)
    raise RuntimeError(f"OPA did not become healthy at {base_url}: {last_err}")


class OpaClient:
    """Minimal client for OPA's REST decision API."""

    def __init__(self, base_url: str):
        self.base_url = base_url

    def decide(self, request_input: dict) -> dict:
        """POST /v1/data/campus/ot_gateway — the endpoint a real PEP calls.

        Returns the structured decision: {"allow": bool, "reason": str}.
        """
        body = json.dumps({"input": request_input}).encode()
        req = urllib.request.Request(
            self.base_url + "/v1/data/campus/ot_gateway",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read())
        return payload["result"]


def _start_opa_server(bundle: Path):
    """Start `opa run -s` on a free port; returns (proc, base_url)."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [
            _opa_bin(), "run", "-s", f"--addr=127.0.0.1:{port}",
            "-b", str(bundle),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    _wait_for_health(base_url)
    return proc, base_url


def _stop_opa_server(proc: subprocess.Popen, bundle: Path) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(bundle, ignore_errors=True)


@pytest.fixture(scope="session")
def opa():
    """OPA server with the real inventory (single source of truth)."""
    bundle = _assemble_bundle()
    proc, base_url = _start_opa_server(bundle)
    try:
        yield OpaClient(base_url)
    finally:
        _stop_opa_server(proc, bundle)


@pytest.fixture(scope="session")
def opa_revoked():
    """OPA server with the same inventory except hvac-01 is revoked.

    OPA refuses runtime data writes to paths owned by a loaded bundle, so
    the modified inventory is loaded as its own bundle instead. This proves
    through the REST API that decisions are data-driven: change the
    inventory, and the decision changes.
    """
    bundle = _assemble_bundle()
    inventory = _inventory_as_json()
    inventory["devices"]["bacnet-controller-hvac-01"]["status"] = "revoked"
    (bundle / "data.yaml").unlink()
    (bundle / "data.json").write_text(json.dumps(inventory))

    proc, base_url = _start_opa_server(bundle)
    try:
        yield OpaClient(base_url)
    finally:
        _stop_opa_server(proc, bundle)
