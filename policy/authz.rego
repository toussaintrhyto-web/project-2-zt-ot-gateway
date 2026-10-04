# campus.ot_gateway — authorization policy for the Zero-Trust OT gateway.
#
# Rego v1 (OPA 1.x). This is the real policy behind the "Illustrative Policy"
# section of the Phase 1 design page: same package, same intent (default deny,
# one allow rule per granted device-to-service path), but data-driven.
# Devices and services are not hardcoded here; they come from
# inventory/inventory.yaml, which is loaded as OPA data (data.devices and
# data.services) so the policy, the tests and the Ansible automation all read
# one single source of truth.
#
# Decision input — one connection request, as asserted by the gateway PEP:
#   {
#     "device_id": "bacnet-controller-hvac-01",  # identity asserted by the gateway
#     "dest_ip":   "172.16.5.10",                # destination service address
#     "dest_port": 47808,                        # destination port (number)
#     "protocol":  "bacnet-ip"                   # protocol used to reach the service
#   }
#
# Decision output:
#   allow  — boolean. Default deny: false unless a rule matches.
#   reason — human-readable explanation, written to the audit log.

package campus.ot_gateway

import rego.v1

# Default deny: every request is denied unless it matches an allow rule.
default allow := false

# Allow a device to reach one of its allowed services when the destination
# IP, port and protocol all match the service entry in the inventory.
allow if {
	device := data.devices[input.device_id]
	device.status == "active"
	some svc_id in device.allowed_services
	svc := data.services[svc_id]
	svc.ip == input.dest_ip
	svc.port == input.dest_port
	svc.protocol == input.protocol
}

# --- Structured decision: reason for the audit log --------------------------
# Exactly one of these rules is defined for any input; the default covers
# malformed requests (missing fields) that no specific rule can describe.

default reason := "deny: request did not match any allow rule"

reason := "allow: active device may reach an allowed service (ip, port and protocol all match)" if allow

reason := "deny: unknown device_id" if {
	not data.devices[input.device_id]
}

reason := sprintf("deny: device %s is not active (status=%v)", [input.device_id, data.devices[input.device_id].status]) if {
	device := data.devices[input.device_id]
	device.status != "active"
}

reason := sprintf("deny: destination %s:%v/%s is not permitted for device %s", [input.dest_ip, input.dest_port, input.protocol, input.device_id]) if {
	device := data.devices[input.device_id]
	device.status == "active"
	not destination_matches(device)
}

# True when (dest_ip, dest_port, protocol) matches one of the device's
# allowed services in the inventory.
destination_matches(device) if {
	some svc_id in device.allowed_services
	svc := data.services[svc_id]
	svc.ip == input.dest_ip
	svc.port == input.dest_port
	svc.protocol == input.protocol
}
