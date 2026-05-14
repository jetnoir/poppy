#!/usr/bin/env bash
# Poppy V5 orchestrated stimulus + observe
#
# Attaches DTrace to a target daemon, then fires malformed XPC messages
# from a client process. Captures both sides.
#
# Usage: sudo ./orchestrate.sh <daemon-name>
#   e.g. sudo ./orchestrate.sh tipsd
set -u

DAEMON="${1:?usage: $0 <daemon-name>}"
POPPY_DIR="$(cd "$(dirname "$0")" && pwd)"
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="${POPPY_DIR}/runs/orch_${DAEMON}_${TS}"

PID=$(pgrep -x "$DAEMON" | head -1)
if [ -z "$PID" ]; then
  echo "[orch] daemon '$DAEMON' not running"; exit 2
fi

echo "[orch] target ${DAEMON} pid=${PID}  ts=${TS}"
echo "[orch] runs prefix: ${PREFIX}"

# Manifest
python3 -c "
import json, subprocess
manifest = {
  'ts': '${TS}', 'daemon': '${DAEMON}', 'pid': ${PID}, 'orchestrated': True,
  'uname': subprocess.check_output(['uname','-a'], text=True).strip(),
}
open('${PREFIX}.manifest.json','w').write(json.dumps(manifest, indent=2))
"

# Start DTrace
dtrace -Z -q -s "${POPPY_DIR}/scripts/xpc_trace.d" -p "${PID}" > "${PREFIX}.dtrace.jsonl" 2>&1 &
DPID=$!
echo "[orch] dtrace pid=${DPID} → ${PREFIX}.dtrace.jsonl"

# Give DTrace 1s to attach probes
sleep 1

# Fire fault injector — may need to be run as the daemon's user, but try from current user
echo "[orch] firing malformed XPC variants..."
python3 "${POPPY_DIR}/inject/xpc_malform.py" --daemon "${DAEMON}" --variants all --out "${PREFIX}.inject.jsonl" 2>&1 | tee "${PREFIX}.inject.stdout"

# Wait a moment for daemon to process
sleep 2

# Stop DTrace
kill "${DPID}" 2>/dev/null
sleep 1

echo ""
echo "[orch] ===== results ====="
echo "[orch] dtrace events:"
grep -cv '^$\|dtrace.begin\|dtrace.end' "${PREFIX}.dtrace.jsonl" 2>/dev/null || echo 0
echo "[orch] inject results:"
wc -l < "${PREFIX}.inject.jsonl"
echo ""
echo "[orch] dtrace sample (first 20 data lines):"
grep -v '^$\|dtrace.begin\|dtrace.end' "${PREFIX}.dtrace.jsonl" | head -20
echo ""
echo "[orch] complete. prefix=${PREFIX}"
