#!/usr/bin/env bash
# Regression suite for the OnCallWorlds patch: boot the binary on the fixture seed and run
# the investigator commands against it as the read-only principal.
#
#   oncallworlds/regress/run.sh [BINARY] [--big]
#
# Needs: python3 with botocore (PYTHON=...), the AWS CLI v2 (AWS=...), curl.
# --big boots on a seed of realistic size and reports boot time and RSS only.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/../../target/release/aws-emulator-ocw}
BIG=${2:-}
PY=${PYTHON:-python3}
AWS_BIN=${AWS:-$HOME/.local/bin/aws}
PORT=${PORT:-9411}
WORK=$(mktemp -d /tmp/ocw-regress.XXXXXX)
mkdir -p "$WORK/home"

cd "$HERE"
"$PY" make_fixture.py "$WORK/seed.json" --credentials-out "$WORK/credentials" $BIG
echo "seed: $(du -h "$WORK/seed.json" | cut -f1)"

t0=$(date +%s.%N)
HOME="$WORK/home" "$BIN" --seed "$WORK/seed.json" -p "$PORT" -t off >"$WORK/emu.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for _ in $(seq 1 600); do
  if curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PORT/__admin/health" 2>/dev/null | grep -q 200; then
    break
  fi
  if ! kill -0 $PID 2>/dev/null; then
    echo "emulator exited:"; tail -20 "$WORK/emu.log"; exit 2
  fi
  sleep 0.1
done
t1=$(date +%s.%N)
echo "boot to healthy: $(echo "$t1 - $t0" | bc) s"
echo "rss after boot: $(grep VmRSS /proc/$PID/status | awk '{print $2/1024 " MB"}')"
grep -h '"ocw_seed"' "$WORK/emu.log" | head -1 || true

if [ "$BIG" = "--big" ]; then
  exit 0
fi
"$PY" run_checks.py --endpoint "https://127.0.0.1:$PORT" \
  --ca "$WORK/home/.aws/emulator/$PORT/ca.pem" --credentials "$WORK/credentials" \
  --root-credentials "$WORK/home/.aws/emulator/$PORT/emulator_credentials" \
  --aws "$AWS_BIN" --out "$WORK/results.tsv"
