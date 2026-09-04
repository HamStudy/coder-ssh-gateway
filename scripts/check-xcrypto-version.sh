#!/bin/bash
# check-xcrypto-version.sh
# Verifies that golang.org/x/crypto is at least v0.52.0
set -euo pipefail

MIN_VERSION="v0.52.0"

current_version=$(go list -m -f '{{.Version}}' golang.org/x/crypto)

# Compare versions using sort -V
if printf '%s\n%s\n' "$MIN_VERSION" "$current_version" | sort -V -C; then
    echo "OK: golang.org/x/crypto $current_version >= $MIN_VERSION"
    exit 0
else
    echo "FAIL: golang.org/x/crypto $current_version is below required minimum $MIN_VERSION"
    echo "This is a security requirement. See: https://pkg.go.dev/vuln/GO-2026-5014"
    exit 1
fi
