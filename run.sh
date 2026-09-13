#!/usr/bin/env bash
# Measurements for taodd/cephtrace PR #192 (osdtrace: ops map -> LRU hash).
#
# Run on a Linux host that runs ceph-osd and has client access to the cluster.
# Use a TEST cluster and a dedicated pool: this creates/removes pr192-* objects
# and runs rados bench writes in that pool.
#
#   sudo env POOL=pr192test ./run.sh all
#
# Steps (each can be run on its own):
#   build   clone cephtrace, build osdtrace for main (PR base) and PR #192
#   env     record kernel / CPU / Ceph / OSD info
#   stall   reproduce the output stall: main vs PR
#   perf    bpf_stats ns/hit + client IOPS: main vs PR, alternating rounds
#   report  print markdown for the PR (results/pr-sections.md)
#   all     all of the above
#
# Settings (environment variables):
#   POOL            test pool (required for stall/perf)
#   OSDTRACE_ARGS   osdtrace target args. Default: none (host ceph-osd).
#                   Containers need e.g. "--id 0,1,2" or "-p <pid>".
#   CEPH_CONF       default /etc/ceph/ceph.conf
#   CEPH_NAME       default client.admin
#   WORKDIR         default ./work next to this script
#   MAIN_BIN PR_BIN use prebuilt osdtrace binaries instead of "build"
#   Stall:  BASELINE_SECS=20 FLOOD_SECS=120 POST_SECS=40 FLOOD_PROCS=16
#           STALL_WINDOW=20 CANARY_OBJECTS=64
#   Perf:   BENCH_SECS=30 BENCH_BS=4096 BENCH_THREADS=16 ROUNDS=2 COOLDOWN=30
#   ATTACH_TIMEOUT=180  seconds to wait for osdtrace to attach
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PY=(python3 "$HERE/pr192.py")
WORKDIR=${WORKDIR:-$HERE/work}
RESULTS=$WORKDIR/results
BIN_DIR=$WORKDIR/bin
MAIN_BIN=${MAIN_BIN:-$BIN_DIR/osdtrace-main}
PR_BIN=${PR_BIN:-$BIN_DIR/osdtrace-pr}
POOL=${POOL:-}
OSDTRACE_ARGS=${OSDTRACE_ARGS:-}
CEPH_CONF=${CEPH_CONF:-/etc/ceph/ceph.conf}
CEPH_NAME=${CEPH_NAME:-client.admin}
BASELINE_SECS=${BASELINE_SECS:-20}
FLOOD_SECS=${FLOOD_SECS:-120}
POST_SECS=${POST_SECS:-40}
FLOOD_PROCS=${FLOOD_PROCS:-16}
STALL_WINDOW=${STALL_WINDOW:-20}
CANARY_OBJECTS=${CANARY_OBJECTS:-64}
BENCH_SECS=${BENCH_SECS:-30}
BENCH_BS=${BENCH_BS:-4096}
BENCH_THREADS=${BENCH_THREADS:-16}
ROUNDS=${ROUNDS:-2}
COOLDOWN=${COOLDOWN:-30}
ATTACH_TIMEOUT=${ATTACH_TIMEOUT:-180}
PR_NUMBER=192

CEPH=(ceph -c "$CEPH_CONF" -n "$CEPH_NAME")
RADOS=(rados -c "$CEPH_CONF" -n "$CEPH_NAME")

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

BG_PIDS=()
TRACER_PID=
STATS_OLD=
cleanup() {
  for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  if [[ -n $TRACER_PID ]]; then kill -INT "$TRACER_PID" 2>/dev/null || true; fi
  if [[ -n $STATS_OLD ]]; then sysctl -qw kernel.bpf_stats_enabled="$STATS_OLD" || true; fi
}
trap cleanup EXIT

need_root() { [[ $(id -u) -eq 0 ]] || die "run as root (sudo)"; }

need_pool() {
  [[ -n $POOL ]] || die "set POOL=<dedicated test pool>"
  local pools
  pools=$("${CEPH[@]}" osd pool ls) || die "ceph osd pool ls failed (check CEPH_CONF/CEPH_NAME)"
  grep -qx -- "$POOL" <<<"$pools" || die "pool '$POOL' not found"
  python3 -c 'import rados' 2>/dev/null || die "python3-rados is required"
}

need_bins() {
  [[ -x $MAIN_BIN && -x $PR_BIN ]] || die "osdtrace binaries missing; run '$0 build' or set MAIN_BIN/PR_BIN"
}

need_clean() {
  if pgrep -x osdtrace >/dev/null || pgrep -x radostrace >/dev/null; then
    die "another osdtrace/radostrace is running; stop it first"
  fi
}

mark() { printf '%s %s\n' "$1" "$(date +%s.%N)" >>"$2/events.txt"; }

# start_tracer <binary> <output prefix>; sets TRACER_PID
start_tracer() {
  local bin=$1 out=$2 waited=0
  # osdtrace never flushes stdout; line-buffer it so rows can be counted live.
  # shellcheck disable=SC2086
  stdbuf -oL "$bin" $OSDTRACE_ARGS >"$out.out" 2>"$out.err" &
  TRACER_PID=$!
  until grep -q "Started to poll from ring buffer" "$out.err" 2>/dev/null; do
    if ! kill -0 "$TRACER_PID" 2>/dev/null; then
      tail -20 "$out.err" >&2
      TRACER_PID=
      die "osdtrace exited during startup (see $out.err)"
    fi
    if (( waited++ >= ATTACH_TIMEOUT )); then
      tail -20 "$out.err" >&2
      die "osdtrace did not attach within ${ATTACH_TIMEOUT}s"
    fi
    sleep 1
  done
  log "osdtrace attached (pid $TRACER_PID)"
}

stop_tracer() {
  [[ -n $TRACER_PID ]] || return 0
  kill -INT "$TRACER_PID" 2>/dev/null || true
  wait "$TRACER_PID" 2>/dev/null || true
  TRACER_PID=
}

cmd_build() {
  local src=$WORKDIR/src base
  for t in git make clang g++; do command -v $t >/dev/null || die "$t not found (see doc/building.md)"; done
  mkdir -p "$WORKDIR" "$BIN_DIR" "$RESULTS"
  if [[ ! -d $src/.git ]]; then
    git clone https://github.com/taodd/cephtrace.git "$src"
  fi
  git -C "$src" fetch origin \
    "+refs/heads/main:refs/remotes/origin/main" \
    "+refs/pull/$PR_NUMBER/head:refs/remotes/origin/pr$PR_NUMBER"
  base=$(git -C "$src" merge-base origin/main "origin/pr$PR_NUMBER")
  log "PR diff against its base:"
  git -C "$src" diff --stat "$base" "origin/pr$PR_NUMBER" >&2

  : >"$RESULTS/commits.txt"
  build_one main "$base"
  build_one pr "origin/pr$PR_NUMBER"
  cat "$RESULTS/commits.txt" >&2
}

build_one() {
  local name=$1 rev=$2 wt=$WORKDIR/wt-$1
  if [[ -d $wt ]]; then
    git -C "$wt" checkout -q --detach "$rev"
  else
    git -C "$WORKDIR/src" worktree add -q --detach "$wt" "$rev"
  fi
  git -C "$wt" submodule update --init --recursive
  make -C "$wt" -j"$(nproc)" osdtrace
  install -D -m 0755 "$wt/osdtrace" "$BIN_DIR/osdtrace-$name"
  echo "$name=$(git -C "$wt" rev-parse --short HEAD)" >>"$RESULTS/commits.txt"
}

cmd_env() {
  mkdir -p "$RESULTS"
  local f=$RESULTS/env.txt osd_pid deploy=packages
  osd_pid=$(pgrep -x ceph-osd | head -1 || true)
  if [[ -n $osd_pid ]] && grep -Eq 'docker|libpod|containerd|kubepods' "/proc/$osd_pid/cgroup" 2>/dev/null; then
    deploy=containers
  fi
  "${CEPH[@]}" versions -f json >"$RESULTS/ceph-versions.json" 2>/dev/null || true
  {
    echo "date=$(date -Is)"
    echo "kernel=$(uname -r)"
    echo "os=$(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "cpu_model=$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)"
    echo "nproc=$(nproc)"
    echo "cpu_possible=$(cat /sys/devices/system/cpu/possible)"
    echo "ceph_osd_version=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(", ".join(k.split(" (")[0].replace("ceph version ","") for k in d.get("osd",{})))' "$RESULTS/ceph-versions.json" 2>/dev/null || echo "?")"
    echo "osds_total=$("${CEPH[@]}" osd stat -f json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["num_osds"])' 2>/dev/null || echo "?")"
    echo "osds_local=$(pgrep -x ceph-osd | wc -l)"
    echo "deploy=$deploy"
    echo "osdtrace_args=${OSDTRACE_ARGS:-<none>}"
    echo "pool=${POOL:-}"
    [[ -n $POOL ]] && echo "pool_size=$("${CEPH[@]}" osd pool get "$POOL" size -f json | python3 -c 'import json,sys; print(json.load(sys.stdin)["size"])')"
    echo "canary_objects=$CANARY_OBJECTS"
    echo "bench_secs=$BENCH_SECS"
    echo "bench_bs=$BENCH_BS"
    echo "bench_threads=$BENCH_THREADS"
  } >"$f"
  cat "$f" >&2
}

run_stall_variant() {
  local variant=$1 bin=$2 d=$RESULTS/stall-$1
  rm -rf "$d"; mkdir -p "$d"
  need_clean
  log "stall/$variant: starting osdtrace"
  start_tracer "$bin" "$d/osdtrace"

  "${PY[@]}" canary --conf "$CEPH_CONF" --name "$CEPH_NAME" --pool "$POOL" \
    --objects "$CANARY_OBJECTS" --counter "$d/canary.cnt" &
  local canary=$!; BG_PIDS+=("$canary")
  "${PY[@]}" sample --pid "$TRACER_PID" --rows "$d/osdtrace.out" --csv "$d/timeline.csv" \
    --counter "flood=$d/flood.cnt" --counter "canary=$d/canary.cnt" &
  local sampler=$!; BG_PIDS+=("$sampler")

  mark baseline_start "$d"
  log "stall/$variant: baseline ${BASELINE_SECS}s (canary only)"
  sleep "$BASELINE_SECS"
  if ! grep -qE '^osd [0-9]+ pg [^ ]+ (op_r|op_w|subop_w) ' "$d/osdtrace.out"; then
    log "WARNING: no op rows during baseline. The canary objects may not map to traced OSDs,"
    log "         or DWARF did not resolve. Check $d/osdtrace.err; consider tracing all OSDs on this host."
  fi

  mark flood_start "$d"
  log "stall/$variant: missing-object flood ${FLOOD_SECS}s x ${FLOOD_PROCS} procs"
  "${PY[@]}" flood --conf "$CEPH_CONF" --name "$CEPH_NAME" --pool "$POOL" \
    --procs "$FLOOD_PROCS" --duration "$FLOOD_SECS" --counter "$d/flood.cnt" >"$d/flood.log"
  mark flood_stop "$d"
  log "stall/$variant: flood stopped, watching ${POST_SECS}s"
  sleep "$POST_SECS"
  mark end "$d"

  kill "$sampler" "$canary" 2>/dev/null || true
  wait "$sampler" "$canary" 2>/dev/null || true
  stop_tracer

  "${PY[@]}" analyze-stall --dir "$d" --window "$STALL_WINDOW" >"$d/summary.json"
  cat "$d/summary.json" >&2
}

cmd_stall() {
  need_root; need_pool; need_bins
  run_stall_variant main "$MAIN_BIN"
  log "cooldown ${COOLDOWN}s"; sleep "$COOLDOWN"
  run_stall_variant pr "$PR_BIN"
  "${PY[@]}" canary --conf "$CEPH_CONF" --name "$CEPH_NAME" --pool "$POOL" \
    --objects "$CANARY_OBJECTS" --cleanup
}

run_bench() {
  local name=$1 d=$2
  "${RADOS[@]}" -p "$POOL" bench "$BENCH_SECS" write -b "$BENCH_BS" -t "$BENCH_THREADS" \
    --run-name "pr${PR_NUMBER}-$name" >"$d/bench.log" 2>&1
  grep "Average IOPS" "$d/bench.log" >&2 || true
}

run_perf_cell() {
  local variant=$1 bin=$2 round=$3 d=$RESULTS/perf/$1-r$3
  rm -rf "$d"; mkdir -p "$d"
  need_clean
  log "perf/$variant round $round"
  start_tracer "$bin" "$d/osdtrace"
  sleep 5
  "${PY[@]}" snapshot --pid "$TRACER_PID" --out "$d/before.json"
  run_bench "$variant-r$round" "$d"
  "${PY[@]}" snapshot --pid "$TRACER_PID" --out "$d/after.json"
  stop_tracer
  log "cooldown ${COOLDOWN}s"; sleep "$COOLDOWN"
}

cmd_perf() {
  need_root; need_pool; need_bins
  [[ -e /proc/sys/kernel/bpf_stats_enabled ]] || die "kernel lacks kernel.bpf_stats_enabled (needs >= 5.8)"
  STATS_OLD=$(sysctl -n kernel.bpf_stats_enabled)
  sysctl -qw kernel.bpf_stats_enabled=1

  mkdir -p "$RESULTS/perf/notracer"
  need_clean
  log "perf: client baseline without tracer"
  run_bench notracer "$RESULTS/perf/notracer"
  sleep "$COOLDOWN"

  local r
  for (( r = 1; r <= ROUNDS; r++ )); do
    run_perf_cell main "$MAIN_BIN" "$r"
    run_perf_cell pr "$PR_BIN" "$r"
  done
}

cmd_report() {
  "${PY[@]}" report --results "$RESULTS" | tee "$RESULTS/pr-sections.md"
  log "saved $RESULTS/pr-sections.md"
}

case ${1:-} in
  build)  cmd_build ;;
  env)    cmd_env ;;
  stall)  cmd_stall ;;
  perf)   cmd_perf ;;
  report) cmd_report ;;
  all)
    need_root; need_pool
    if [[ ! -x $MAIN_BIN || ! -x $PR_BIN ]]; then cmd_build; fi
    cmd_env; cmd_stall; cmd_perf; cmd_report ;;
  *) awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 1 ;;
esac
