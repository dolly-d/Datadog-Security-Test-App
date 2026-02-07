#!/usr/bin/env bash
set -euo pipefail

echo "[1] Spawn shells / common utils"
sh -c 'echo hello from sh'
bash -c 'echo hello from bash' || true

echo "[2] Write into suspicious-ish paths (safe lab locations)"
mkdir -p /tmp/lab_artifacts
echo "test" > /tmp/lab_artifacts/marker.txt

echo "[3] Network-ish behavior"
curl -sS https://example.com >/dev/null || true
nc -vz example.com 80 || true

echo "[4] Create and execute a temp script"
cat >/tmp/lab_artifacts/runme.sh <<'EOF'
#!/bin/sh
echo "running temp script"
id || true
EOF
chmod +x /tmp/lab_artifacts/runme.sh
/tmp/lab_artifacts/runme.sh || true

echo "Done."
