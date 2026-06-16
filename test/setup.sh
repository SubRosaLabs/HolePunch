#!/bin/bash
# One-time setup: build binaries and generate the operator keypair.
# Creates test/keys/operator.key  and  test/authorized_keys.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLIENT="$PROJECT_ROOT/bin/holepunch-client"

# Build if binaries are missing.
if [ ! -f "$CLIENT" ]; then
    echo "[setup] building binaries..."
    make -C "$PROJECT_ROOT" build
fi

mkdir -p "$SCRIPT_DIR/keys"

if [ -f "$SCRIPT_DIR/keys/operator.key" ]; then
    echo "[setup] keypair already exists — skipping keygen"
else
    echo "[setup] generating operator keypair..."
    "$CLIENT" -keygen "$SCRIPT_DIR/keys/operator.key"
    echo "[setup] keypair written to test/keys/"
fi

# The .pub file is already in authorized_keys line format (base64 pubkey).
cp "$SCRIPT_DIR/keys/operator.key.pub" "$SCRIPT_DIR/authorized_keys"
echo "[setup] authorized_keys:"
cat "$SCRIPT_DIR/authorized_keys"
echo ""
echo "[setup] done.  Run:  cd test && docker compose up  (or use run_test.sh)"
