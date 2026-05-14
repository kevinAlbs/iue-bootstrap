#!/bin/bash
set -e

export PYMONGOCRYPT_LIB=/Users/kevin.albertson/code/c-bootstrap/install/libmongocrypt-1.18.1/lib/libmongocrypt.dylib
export CRYPT_SHARED_PATH=/Users/kevin.albertson/bin/mongodl/crypt_shared/latest-build/lib/mongo_crypt_v1.dylib
export MONGODB_URI="mongodb://localhost:27777/?directConnection=true"

cd "$(dirname "$0")"

echo "=== insert-find.py ==="
uv run insert-find.py

echo "=== test-operators.py ==="
uv run test-operators.py

echo "=== test-sensitivity.py ==="
uv run test-sensitivity.py

echo "=== test-auto-explicit-mix.py ==="
uv run test-auto-explicit-mix.py

echo ""
echo "All tests passed."
