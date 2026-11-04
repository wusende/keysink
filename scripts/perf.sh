#!/usr/bin/env bash
# keysink 性能测试编排 — 方案与指标定义见 docs/perf-test-plan.md。
#
# 三进程分离:ksbench upstream(假上游)/ keysink serve(被测网关)/ ksbench bench(负载)。
# 每场景跑 PERF_ROUNDS 轮,JSON 行写入 rounds.jsonl,最后由 perf_aggregate.py
# 汇总为 summary.md(轮间取中位数,成对场景计算网关开销)。
#
# 可用环境变量:
#   PERF_ROUNDS  每场景轮数(默认 3)
#   PERF_DURATION 常规场景时长秒(默认 15)
#   PERF_SOAK    soak 时长秒(默认 600;CI/调试可调小)
#   PERF_SKIP_SOAK=1 跳过 soak 场景
#
# 平台:Linux / macOS / WSL。Windows 原生 bash(Git Bash/MSYS2)不支持,见脚本开头的拦截。
set -euo pipefail

# Windows 上只有 WSL 能完整跑:原生 bash 环境(Git Bash/MSYS2)既没有
# /dev/tcp 端口探测,ps 也不支持 -o rss(RSS 采样产出空值,聚合阶段
# ValueError),perf 数据会半残。趁早拦下,而不是让人跑到一半对着坏数据排障。
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "FATAL: perf.sh does not run under Git Bash/MSYS2 (no /dev/tcp, ps lacks -o rss; the RSS aggregate would fail)." >&2
    echo "Run it under WSL instead: wsl bash scripts/perf.sh" >&2
    exit 1
    ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN="$ROOT/target/release/keysink"
KSBENCH="$ROOT/target/release/ksbench"
STAMP="$(date +%Y%m%d-%H%M%S)"
RESULTS="$ROOT/perf/results/$STAMP"
mkdir -p "$RESULTS"

ROUNDS="${PERF_ROUNDS:-3}"
DURATION="${PERF_DURATION:-15}"
SOAK="${PERF_SOAK:-600}"

UP_PORT=19191
GW_PORT=18787

UP_PID=""
GW_PID=""
# 失败标记:run_bench 轮失败 / 聚合失败 / 微基准失败都置 1,脚本最终以
# 非零退出,CI 与调用方才能感知;否则缺轮只能靠人眼翻 summary。
FAILED=0
# 后台 bench(S7 reload / S8 soak)进程:set -e 中途退出时 cleanup 必须
# 一并杀掉,否则它们对着已死的网关空转发最长 SOAK 秒。
RELOAD_BENCH=""
SOAK_SMALL=""
SOAK_SSE=""

# 端口被占时基线会打到别人身上而静默产出错误数据(健康检查探的是端口
# 上的任何进程),开工前先确认两个端口都没人。fd 开在子 shell 里,连接
# 成功即说明端口有人,子 shell 退出连接随之关闭。
for _port in "$UP_PORT" "$GW_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$_port") 2>/dev/null; then
    echo "FATAL: port $_port already in use (先释放端口再跑)" >&2
    exit 1
  fi
done

cleanup() {
  [ -n "$RELOAD_BENCH" ] && kill "$RELOAD_BENCH" 2>/dev/null || true
  [ -n "$SOAK_SMALL" ] && kill "$SOAK_SMALL" 2>/dev/null || true
  [ -n "$SOAK_SSE" ] && kill "$SOAK_SSE" 2>/dev/null || true
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null || true
}
trap cleanup EXIT

log() { printf '\n===== %s =====\n' "$*"; }

# ---------------------------------------------------------------------------
# 环境记录 + 构建
# ---------------------------------------------------------------------------
log "env + build"
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "os: $(uname -s -r -m)"
  # Model / cores / memory, per platform: macOS reports P/E core split via
  # sysctl, Linux falls back to /proc. Unknown fields are simply absent —
  # env.txt feeds the summary header, nothing parses it.
  case "$(uname -s)" in
    Darwin)
      sw_vers
      sysctl -n hw.model hw.ncpu hw.perflevel0.logicalcpu hw.perflevel1.logicalcpu hw.memsize
      ;;
    Linux)
      grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs || true
      echo "cores: $(nproc)"
      awk '/MemTotal/ {printf "mem_bytes: %s\n", $2*1024}' /proc/meminfo
      ;;
  esac
  "$BIN" --version || true
} >"$RESULTS/env.txt" 2>&1
cat "$RESULTS/env.txt"

cargo build --release --locked
cargo build --release --locked -p ksbench

# ---------------------------------------------------------------------------
# 基础设施:上游 / vault / 网关
# ---------------------------------------------------------------------------
log "start upstream"
"$KSBENCH" upstream --port "$UP_PORT" >"$RESULTS/upstream.log" 2>&1 &
UP_PID=$!
# 与 start_gw 同款存活探测:bind 失败(端口被占)时进程会死,没有这个
# 检查的话 d/* 直连基线全部打到端口占用者身上。
for _ in $(seq 50); do
  kill -0 "$UP_PID" 2>/dev/null || {
    echo "FATAL: upstream died during startup" >&2
    tail -5 "$RESULTS/upstream.log" >&2
    exit 1
  }
  (exec 3<>"/dev/tcp/127.0.0.1/$UP_PORT") 2>/dev/null && break
  sleep 0.1
done

VAULT="$(mktemp -d)"
ks() { "$BIN" --home "$VAULT" "$@"; }
# route add prints the vkey only once; grab it (smoke.sh pattern).
new_vkey() { sed -n 's/^vkey: //p'; }

log "init vault + route"
printf 'perf-pass\n' | ks init --password-stdin >/dev/null
VKEY="$(printf 'real-perf-key\n' | ks route add bench \
  --base-url "http://127.0.0.1:$UP_PORT" --auth x-api-key | new_vkey)"
if [ -z "$VKEY" ]; then echo "FATAL: no vkey captured" >&2; exit 1; fi

GW_LOG="$RESULTS/gateway.log"
GW_PID_FILE="$RESULTS/gw.pid"
# 默认 warn:每请求 info 行在 60k RPS 下 15s 就写 ~180MB(曾经撑爆磁盘),
# 日志本身的开销单独在 S10 里做受控对比。GW_RUST_LOG=info 可覆盖。
start_gw() { # $@ = extra serve flags
  RUST_LOG="${GW_RUST_LOG:-warn}" "$BIN" --home "$VAULT" serve --listen "127.0.0.1:$GW_PORT" "$@" \
    >"$GW_LOG" 2>&1 &
  GW_PID=$!
  echo "$GW_PID" >"$GW_PID_FILE"
  for _ in $(seq 100); do
    # 健康检查探到的是端口上的任何进程:若本进程已死(bind 失败,比如上一
    # 场景的网关没停),curl 会探到旧网关并误报成功,被测对象被静默换掉。
    kill -0 "$GW_PID" 2>/dev/null || {
      echo "FATAL: gateway process died during startup" >&2
      tail -5 "$GW_LOG" >&2
      exit 1
    }
    curl -sf "http://127.0.0.1:$GW_PORT/__keysink/health" >/dev/null && return 0
    sleep 0.1
  done
  echo "FATAL: gateway did not become healthy" >&2
  tail -5 "$GW_LOG" >&2
  exit 1
}
stop_gw() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  wait "$GW_PID" 2>/dev/null || true
  rm -f "$GW_PID_FILE"
  GW_PID=""
}

# 网关 RSS 采样(每秒一行,与 markers.log 时间戳对齐)。PID 从文件读:
# 采样器先于 start_gw fork,环境变量捕获不到后来的值。
RSS_FILE="$RESULTS/rss.csv"
MARKERS="$RESULTS/markers.log"
touch "$RSS_FILE" "$MARKERS"
rss_sampler() {
  while :; do
    if [ -f "$GW_PID_FILE" ]; then
      pid="$(cat "$GW_PID_FILE")"
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$(date +%s),$(ps -o rss= -p "$pid" | tr -d ' ')" >>"$RSS_FILE"
      fi
    fi
    sleep 1
  done
}
rss_sampler & RSS_SAMPLER=$!
cleanup() {
  kill "$RSS_SAMPLER" 2>/dev/null || true
  [ -n "$RELOAD_BENCH" ] && kill "$RELOAD_BENCH" 2>/dev/null || true
  [ -n "$SOAK_SMALL" ] && kill "$SOAK_SMALL" 2>/dev/null || true
  [ -n "$SOAK_SSE" ] && kill "$SOAK_SSE" 2>/dev/null || true
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null || true
}
trap cleanup EXIT

DIRECT="http://127.0.0.1:$UP_PORT"
GATEWAY="http://127.0.0.1:$GW_PORT"
AUTH=(--header "x-api-key: $VKEY")

# run_bench LABEL ROUNDS_OVERRIDE args…  → rounds.jsonl
run_bench() {
  local label=$1 rounds=$2
  shift 2
  echo "$(date +%s) START $label" >>"$MARKERS"
  local r
  for r in $(seq "$rounds"); do
    "$KSBENCH" bench "$@" --label "$label" \
      >>"$RESULTS/rounds.jsonl" 2>>"$RESULTS/ksbench.err" \
      || {
        echo "$(date +%s) FAIL $label round $r" >>"$MARKERS"
        FAILED=1
      }
  done
  echo "$(date +%s) END $label" >>"$MARKERS"
}

gw() { # gateway target with auth headers
  echo "$GATEWAY$1"
}

# ---------------------------------------------------------------------------
log "S1 baseline (direct) + S2 small-request ladder"
start_gw

# 直连基线:小请求(并发锚点 8/64)
for c in 8 64; do
  run_bench "d/small_c$c" "$ROUNDS" --target "$DIRECT/echo?size=1024" \
    --concurrency "$c" --duration "$DURATION"
done

# 经网关:并发阶梯
for c in 1 8 32 64 128 256; do
  run_bench "g/small_c$c" "$ROUNDS" --target "$(gw /echo?size=1024)" \
    "${AUTH[@]}" --concurrency "$c" --duration "$DURATION"
done

# ---------------------------------------------------------------------------
log "S3 SSE"
SSE_URL="/sse?chunks=100&chunk_size=64&interval_ms=0&first_delay_ms=50"
run_bench "d/sse_ttfb" "$ROUNDS" --target "$DIRECT$SSE_URL" --method GET --sse \
  --concurrency 1 --max-requests 50 --duration 120
run_bench "g/sse_ttfb" "$ROUNDS" --target "$(gw "$SSE_URL")" --method GET --sse \
  "${AUTH[@]}" --concurrency 1 --max-requests 50 --duration 120

# 长流吞吐:1000 块无间隔,每块转发开销 = 总时差 / 块数
LONG_URL="/sse?chunks=1000&chunk_size=512&interval_ms=0"
run_bench "d/sse_long" "$ROUNDS" --target "$DIRECT$LONG_URL" --method GET --sse \
  --concurrency 8 --max-requests 24 --duration 300
run_bench "g/sse_long" "$ROUNDS" --target "$(gw "$LONG_URL")" --method GET --sse \
  "${AUTH[@]}" --concurrency 8 --max-requests 24 --duration 300

# 仿真节奏流:200 块 × 8ms(接近真实 LLM 输出节奏),看块间隔增量
PACED_URL="/sse?chunks=200&chunk_size=512&interval_ms=8"
run_bench "d/sse_paced" "$ROUNDS" --target "$DIRECT$PACED_URL" --method GET --sse \
  --concurrency 8 --max-requests 16 --duration 300
run_bench "g/sse_paced" "$ROUNDS" --target "$(gw "$PACED_URL")" --method GET --sse \
  "${AUTH[@]}" --concurrency 8 --max-requests 16 --duration 300

# 大流:2000 × 8KB ≈ 16MB
BIGSSE_URL="/sse?chunks=2000&chunk_size=8192&interval_ms=0"
run_bench "d/sse_big" "$ROUNDS" --target "$DIRECT$BIGSSE_URL" --method GET --sse \
  --concurrency 2 --max-requests 4 --duration 300
run_bench "g/sse_big" "$ROUNDS" --target "$(gw "$BIGSSE_URL")" --method GET --sse \
  "${AUTH[@]}" --concurrency 2 --max-requests 4 --duration 300

# 非流式大响应(逐块转发 + 每块空闲超时包装路径)
run_bench "d/json32mb" "$ROUNDS" --target "$DIRECT/json?size=33554432" \
  --concurrency 2 --max-requests 6 --duration 300
run_bench "g/json32mb" "$ROUNDS" --target "$(gw /json?size=33554432)" \
  "${AUTH[@]}" --concurrency 2 --max-requests 6 --duration 300

# ---------------------------------------------------------------------------
log "S4 large request bodies"
# 33554432 恰好等于网关默认 --max-body-mb 32(上限含端点,压线通过):
# 场景本意就是"最大默认 body",但任何一侧改动一字节就会 413——动这个
# 数字前先对齐两侧。
for size in 1048576 8388608 33554432; do
  for kind in plain stream_true marker_in_string; do
    run_bench "g/body_${size}_${kind}" "$ROUNDS" --target "$(gw /echo?size=1024)" \
      "${AUTH[@]}" --concurrency 1 --max-requests 10 --duration 300 \
      --body-size "$size" --body-kind "$kind"
  done
done
# 直连锚点(8MB plain,上游读 body 的裸成本)
run_bench "d/body_8388608_plain" "$ROUNDS" --target "$DIRECT/echo?size=1024" \
  --concurrency 1 --max-requests 10 --duration 300 --body-size 8388608 --body-kind plain

# ---------------------------------------------------------------------------
log "S5 concurrency beyond the cap (max-concurrent 8, 64 workers)"
stop_gw
start_gw --max-concurrent 8
run_bench "g/capped8_c64" "$ROUNDS" --target "$(gw /echo?size=1024)" \
  "${AUTH[@]}" --concurrency 64 --duration "$DURATION"
stop_gw
start_gw

# ---------------------------------------------------------------------------
log "S6 audit on vs off"
run_bench "g/audit_off_c32" "$ROUNDS" --target "$(gw /echo?size=1024)" \
  "${AUTH[@]}" --concurrency 32 --duration "$DURATION"
stop_gw
start_gw --audit-log "$RESULTS/audit.jsonl"
run_bench "g/audit_on_c32" "$ROUNDS" --target "$(gw /echo?size=1024)" \
  "${AUTH[@]}" --concurrency 32 --duration "$DURATION"
stop_gw

# ---------------------------------------------------------------------------
log "S10 per-request log cost (info vs warn)"
# 每个配置一个独立的网关进程:start_gw 前必须没有存活网关,否则新进程 bind
# 失败退出、健康检查却探到旧网关误报成功,三个场景会测成同一个配置。
# warn→/dev/null:无每请求日志的基线;info→/dev/null:格式化+写系统调用的
# CPU 成本;info→文件:再加落盘成本(1 轮即删,防止日志膨胀)。
GW_LOG=/dev/null start_gw
run_bench "g/logwarn_devnull_c32" "$ROUNDS" --target "$(gw /echo?size=1024)" \
  "${AUTH[@]}" --concurrency 32 --duration "$DURATION"
stop_gw
GW_LOG=/dev/null GW_RUST_LOG=info start_gw
run_bench "g/loginfo_devnull_c32" "$ROUNDS" --target "$(gw /echo?size=1024)" \
  "${AUTH[@]}" --concurrency 32 --duration "$DURATION"
stop_gw
GW_LOG="$RESULTS/gateway_info.log" GW_RUST_LOG=info start_gw
run_bench "g/loginfo_file_c32" 1 --target "$(gw /echo?size=1024)" \
  "${AUTH[@]}" --concurrency 32 --duration "$DURATION"
stop_gw
rm -f "$RESULTS/gateway_info.log"

start_gw

# ---------------------------------------------------------------------------
log "S7 hot reload under load"
"$KSBENCH" bench --target "$(gw /echo?size=1024)" "${AUTH[@]}" \
  --concurrency 32 --duration 45 --label "g/reload_under_load" \
  >"$RESULTS/reload.json" 2>>"$RESULTS/ksbench.err" &
RELOAD_BENCH=$!
sleep 5
echo "$(date +%s) START reloads" >>"$MARKERS"
for i in 1 2 3; do
  printf 'real-perf-key\n' | ks route add "hot$i" \
    --base-url "http://127.0.0.1:$UP_PORT" --auth x-api-key >/dev/null
  sleep 4
done
# mtime 扰动:watcher 应重解锁但快照内容等价
for i in 1 2; do touch "$VAULT/store.age"; sleep 4; done
wait "$RELOAD_BENCH" || FAILED=1
echo "$(date +%s) END reloads" >>"$MARKERS"
RELOAD_BENCH=""

# ---------------------------------------------------------------------------
log "S8 soak (mixed: small + paced SSE)"
if [ "${PERF_SKIP_SOAK:-0}" != "1" ]; then
  echo "$(date +%s) START soak" >>"$MARKERS"
  "$KSBENCH" bench --target "$(gw /echo?size=1024)" "${AUTH[@]}" \
    --concurrency 24 --duration "$SOAK" --label "g/soak_small" \
    >"$RESULTS/soak_small.json" 2>>"$RESULTS/ksbench.err" &
  SOAK_SMALL=$!
  "$KSBENCH" bench --target "$(gw "$PACED_URL")" --method GET --sse "${AUTH[@]}" \
    --concurrency 8 --duration "$SOAK" --label "g/soak_sse" \
    >"$RESULTS/soak_sse.json" 2>>"$RESULTS/ksbench.err" &
  SOAK_SSE=$!
  wait "$SOAK_SMALL" || FAILED=1
  wait "$SOAK_SSE" || FAILED=1
  SOAK_SMALL=""
  SOAK_SSE=""
  cat "$RESULTS/soak_small.json" >>"$RESULTS/rounds.jsonl"
  cat "$RESULTS/soak_sse.json" >>"$RESULTS/rounds.jsonl"
  echo "$(date +%s) END soak" >>"$MARKERS"
else
  echo "soak skipped (PERF_SKIP_SOAK=1)"
fi

stop_gw

# ---------------------------------------------------------------------------
log "S9 micro-benchmarks (cargo perf_ tests, release)"
cargo test --release --locked perf_ -- --nocapture \
  >"$RESULTS/micro.txt" 2>&1 || {
  echo "micro tests FAILED" >>"$RESULTS/micro.txt"
  FAILED=1
}
grep -E "perf/" "$RESULTS/micro.txt" || true

# ---------------------------------------------------------------------------
log "aggregate"
python3 scripts/perf_aggregate.py \
  --results "$RESULTS" >"$RESULTS/aggregate.log" 2>&1 || {
  echo "aggregate FAILED"
  cat "$RESULTS/aggregate.log"
  FAILED=1
}
kill "$RSS_SAMPLER" 2>/dev/null || true
kill "$UP_PID" 2>/dev/null || true

echo
echo "results in: $RESULTS"
echo "summary:    $RESULTS/summary.md"
if [ "$FAILED" -ne 0 ]; then
  echo "STATUS: FAILED(轮失败/聚合失败,详见 markers.log、ksbench.err、aggregate.log)"
fi
exit "$FAILED"
