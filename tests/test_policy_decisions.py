"""Pytest cases for OPA's REST decision API.

Mirrors the native Rego test matrix (policy/authz_test.rego) through the
HTTP endpoint a real PEP would call:

    POST /v1/data/campus/ot_gateway   {"input": {device_id, dest_ip, dest_port, protocol}}

Every allow case has at least one negative control that differs by a single
field; default deny is proven with empty and malformed inputs.
"""

import pytest

# (case id, request input, expected allow) — same matrix as the native tests.
CASES = [
    # Authorized flows.
    (
        "allow-hvac01-to-plant",
        {"device_id": "bacnet-controller-hvac-01", "dest_ip": "172.16.5.10", "dest_port": 47808, "protocol": "bacnet-ip"},
        True,
    ),
    (
        "allow-temp01-to-historian",
        {"device_id": "mqtt-sensor-temp-01", "dest_ip": "172.16.5.11", "dest_port": 1883, "protocol": "mqtt"},
        True,
    ),
    # Single-field negative controls.
    (
        "deny-hvac01-wrong-port",
        {"device_id": "bacnet-controller-hvac-01", "dest_ip": "172.16.5.10", "dest_port": 47809, "protocol": "bacnet-ip"},
        False,
    ),
    (
        "deny-hvac01-wrong-protocol",
        {"device_id": "bacnet-controller-hvac-01", "dest_ip": "172.16.5.10", "dest_port": 47808, "protocol": "mqtt"},
        False,
    ),
    (
        "deny-hvac01-unauthorized-service",
        {"device_id": "bacnet-controller-hvac-01", "dest_ip": "172.16.5.11", "dest_port": 47808, "protocol": "bacnet-ip"},
        False,
    ),
    (
        "deny-temp01-wrong-port",
        {"device_id": "mqtt-sensor-temp-01", "dest_ip": "172.16.5.11", "dest_port": 8883, "protocol": "mqtt"},
        False,
    ),
    (
        "deny-temp01-wrong-protocol",
        {"device_id": "mqtt-sensor-temp-01", "dest_ip": "172.16.5.11", "dest_port": 1883, "protocol": "bacnet-ip"},
        False,
    ),
    # Lateral movement.
    (
        "deny-lateral-ot-to-ot",
        {"device_id": "bacnet-controller-hvac-02", "dest_ip": "10.20.41.5", "dest_port": 47808, "protocol": "bacnet-ip"},
        False,
    ),
    (
        "deny-lateral-ot-to-it",
        {"device_id": "bacnet-controller-hvac-01", "dest_ip": "172.16.9.4", "dest_port": 443, "protocol": "https"},
        False,
    ),
    # Identity negative controls.
    (
        "deny-unknown-device",
        {"device_id": "bacnet-controller-hvac-99", "dest_ip": "172.16.5.10", "dest_port": 47808, "protocol": "bacnet-ip"},
        False,
    ),
    # Malformed input: default deny is proven.
    ("deny-empty-input", {}, False),
    (
        "deny-missing-fields",
        {"device_id": "bacnet-controller-hvac-01"},
        False,
    ),
]


@pytest.mark.parametrize(
    "case_id, request_input, expected", CASES, ids=[c[0] for c in CASES]
)
def test_decision_via_rest_api(opa, case_id, request_input, expected):
    result = opa.decide(request_input)
    assert result["allow"] is expected, f"{case_id}: {result}"
    # Structured decision: every response carries a non-empty reason for the audit log.
    assert isinstance(result.get("reason"), str) and result["reason"], f"{case_id}: {result}"


def test_allow_reason(opa):
    result = opa.decide(
        {"device_id": "bacnet-controller-hvac-01", "dest_ip": "172.16.5.10", "dest_port": 47808, "protocol": "bacnet-ip"}
    )
    assert result["reason"].startswith("allow:")


def test_unknown_device_reason(opa):
    result = opa.decide(
        {"device_id": "bacnet-controller-hvac-99", "dest_ip": "172.16.5.10", "dest_port": 47808, "protocol": "bacnet-ip"}
    )
    assert result["reason"] == "deny: unknown device_id"


def test_revoked_device_denied_via_rest(opa_revoked):
    """Data-driven design: changing the inventory changes the decision.

    The same request that is allowed with the real inventory (see
    test_decision_via_rest_api[allow-hvac01-to-plant]) is denied when the
    device's status in the inventory is revoked — evaluated by a second OPA
    server loading the modified inventory, over the same REST endpoint.
    """
    result = opa_revoked.decide(
        {"device_id": "bacnet-controller-hvac-01", "dest_ip": "172.16.5.10", "dest_port": 47808, "protocol": "bacnet-ip"}
    )
    assert result["allow"] is False, result
    assert "status=revoked" in result["reason"], result
