#!/usr/bin/env bash
# Run the native OPA tests against the real inventory.
#
# `opa test` has no --data flag, so this script assembles a temporary bundle:
#   policy/*.rego            -> the policies and tests
#   inventory/inventory.yaml -> data.yaml, landing at the data root
#                                (data.devices / data.services)
#
# Usage: scripts/run_opa_tests.sh [-v]

set -euo pipefail

cd "$(dirname "$0")/.."

bundle="$(mktemp -d)"
trap 'rm -rf "$bundle"' EXIT

cp policy/*.rego "$bundle/"
cp inventory/inventory.yaml "$bundle/data.yaml"

exec opa test -b "$bundle/" "$@"
