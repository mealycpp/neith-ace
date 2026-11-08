#!/usr/bin/env bash
# NEITH-ACE v4 experiments.
#   nohup ./run_all.sh pi4  > pi4.out 2>&1 &     # ClusterHAT host: bench, attacks (both declaration modes),
#                                                 #   baselines, live runs (clean / loss+repair / loss no-repair)
#   ./run_all.sh zero                             # each Pi Zero 2 W: bench only
#   ./run_all.sh sobek                            # SOBEK: bench only (store/verifier role is run separately)
# Optional env:  GNSS_SRC=serial:/dev/ttyACM0  LIDAR_SRC=serialblock:/dev/ttyUSB0:8192  TRIALS=100  XMSS20=1
set -uo pipefail
cd "$(dirname "$0")"
ROLE=${1:-pi4}; HOST=$(hostname); OUT=results; mkdir -p $OUT
LOG=$OUT/run_${HOST}.log
exec > >(tee -a "$LOG") 2>&1
echo "=== NEITH-ACE v4 run_all role=$ROLE host=$HOST $(date -Is)"
uname -a; python3 --version; cat /proc/device-tree/model 2>/dev/null; echo
./build.sh || { echo "BUILD FAILED"; exit 1; }

if [ "$ROLE" = "zero" ] || [ "$ROLE" = "sobek" ]; then
  python3 bench.py --reps 100 --py-reps 3 --xmss-h 10 --xmss-sign-reps 50 --procs 1 2 --out $OUT
else
  H="10 16"; [ "${XMSS20:-0}" = "1" ] && H="10 16 20"
  python3 bench.py --reps 300 --py-reps 5 --xmss-h $H --xmss-sign-reps 200 --procs 1 2 4 --out $OUT
  python3 attacks.py --trials ${TRIALS:-100} --out $OUT                  # signed declarations
  python3 attacks.py --trials ${TRIALS:-100} --decl mac --out $OUT       # MAC-only declarations (baseline)
  python3 baselines.py --trials ${BTRIALS:-30} --out $OUT
  GNSS=${GNSS_SRC:-synth:5.529:8192}; LIDAR=${LIDAR_SRC:-synth:1.432:8192}
  # live pipeline, local store: clean (32 w), loss+repair (12 w), loss without repair (12 w)
  for RUN in "clean 32 0.0 1" "loss_repair 12 0.05 1" "loss_norepair 12 0.05 0"; do
    set -- $RUN
    echo "--- live run: $1 (windows=$2 drop=$3 repair=$4) gnss=$GNSS lidar=$LIDAR"
    python3 live.py serve --windows $2 --drop $3 --repair $4 --warmup 20 --out $OUT/live_$1 &
    SP=$!; sleep 3
    python3 live.py adapter --id 0 --source "$GNSS"  --out $OUT/live_$1 > $OUT/adapter0_$1.log 2>&1 &
    python3 live.py adapter --id 1 --source "$LIDAR" --out $OUT/live_$1 > $OUT/adapter1_$1.log 2>&1 &
    wait $SP
    pkill -f "live.py adapter" 2>/dev/null; sleep 2
  done
fi
tar czf neith-ace-results_${HOST}.tgz $OUT
echo "=== DONE $(date -Is). Send back: $(pwd)/neith-ace-results_${HOST}.tgz"
