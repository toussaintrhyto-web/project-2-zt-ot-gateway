# Native OPA tests for the campus.ot_gateway authorization policy.
#
# Run against the real inventory (single source of truth) via the helper:
#   scripts/run_opa_tests.sh -v
# (opa test has no --data flag, so the script assembles a bundle from
#  policy/ plus inventory/inventory.yaml as data.yaml.)
#
# The matrix follows the Phase 2 plan: every allow case has at least one
# negative control that differs by a single field, plus identity and
# malformed-input controls. Default deny is proven with an empty input.

package campus.ot_gateway

import rego.v1

# Build a decision request the way the gateway PEP would.
req(device_id, dest_ip, port, proto) := {
	"device_id": device_id,
	"dest_ip": dest_ip,
	"dest_port": port,
	"protocol": proto,
} if true

# --- Authorized flows --------------------------------------------------------

test_allow_hvac01_to_plant_controller if {
	allow with input as req("bacnet-controller-hvac-01", "172.16.5.10", 47808, "bacnet-ip")
}

test_allow_temp01_to_historian if {
	allow with input as req("mqtt-sensor-temp-01", "172.16.5.11", 1883, "mqtt")
}

# --- Negative controls: single-field deviations from an allow case -----------

test_deny_hvac01_wrong_port if {
	not allow with input as req("bacnet-controller-hvac-01", "172.16.5.10", 47809, "bacnet-ip")
}

test_deny_hvac01_wrong_protocol if {
	not allow with input as req("bacnet-controller-hvac-01", "172.16.5.10", 47808, "mqtt")
}

test_deny_hvac01_to_unauthorized_service if {
	# bms-historian's address: not in hvac-01's allowed_services.
	not allow with input as req("bacnet-controller-hvac-01", "172.16.5.11", 47808, "bacnet-ip")
}

test_deny_temp01_wrong_port if {
	not allow with input as req("mqtt-sensor-temp-01", "172.16.5.11", 8883, "mqtt")
}

test_deny_temp01_wrong_protocol if {
	not allow with input as req("mqtt-sensor-temp-01", "172.16.5.11", 1883, "bacnet-ip")
}

# --- Lateral movement ---------------------------------------------------------

test_deny_lateral_ot_to_ot if {
	# Compromised controller reaching another OT segment (design page scenario).
	not allow with input as req("bacnet-controller-hvac-02", "10.20.41.5", 47808, "bacnet-ip")
}

test_deny_lateral_ot_to_it if {
	# OT device reaching an IT-core service (design page scenario).
	not allow with input as req("bacnet-controller-hvac-01", "172.16.9.4", 443, "https")
}

# --- Identity negative controls ------------------------------------------------

test_deny_unknown_device if {
	not allow with input as req("bacnet-controller-hvac-99", "172.16.5.10", 47808, "bacnet-ip")
	reason == "deny: unknown device_id" with input as req("bacnet-controller-hvac-99", "172.16.5.10", 47808, "bacnet-ip")
}

test_deny_revoked_device if {
	# Same device and destination as the allow case, but status flipped to revoked.
	updated := object.union(data.devices["bacnet-controller-hvac-01"], {"status": "revoked"})
	devices := object.union(data.devices, {"bacnet-controller-hvac-01": updated})
	not allow with input as req("bacnet-controller-hvac-01", "172.16.5.10", 47808, "bacnet-ip") with data.devices as devices
	reason == "deny: device bacnet-controller-hvac-01 is not active (status=revoked)" with input as req("bacnet-controller-hvac-01", "172.16.5.10", 47808, "bacnet-ip") with data.devices as devices
}

test_deny_inactive_device if {
	updated := object.union(data.devices["mqtt-sensor-temp-01"], {"status": "inactive"})
	devices := object.union(data.devices, {"mqtt-sensor-temp-01": updated})
	not allow with input as req("mqtt-sensor-temp-01", "172.16.5.11", 1883, "mqtt") with data.devices as devices
}

# --- Malformed input: default deny is proven -----------------------------------

test_deny_empty_input if {
	not allow with input as {}
	reason == "deny: request did not match any allow rule" with input as {}
}

test_deny_missing_fields if {
	# device_id only: no destination fields at all.
	not allow with input as {"device_id": "bacnet-controller-hvac-01"}
}
