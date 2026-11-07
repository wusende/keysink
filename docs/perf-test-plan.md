# 性能测试方案

`scripts/perf.sh` 的场景矩阵、指标定义与聚合方式。工具链由三部分组成:

- `perf/ksbench`(`ksbench upstream` / `ksbench bench`)——进程内假上游 + 负载客户端
- `scripts/perf.sh` —— 三进程编排:每场景跑多轮,原始数据落盘
- `scripts/perf_aggregate.py` —— 聚合为 `summary.md` / `summary.json`

README 的「性能 / Performance」小节引用的参考基线即出自这套工具;换机器后以
自己跑出的数字为准。

## 架构:三进程分离

假上游、被测网关、负载客户端是三个独立进程,各绑各的 loopback 端口
(上游 19191,网关 18787)。负载生成不与被测方共享 runtime,直连基线
(`d/…`)与经网关(`g/…`)用同一个客户端、同一个假上游,成对差值
(g/X − d/X)就是网关自身的开销。

两个端口被占用时脚本直接 FATAL 退出:健康检查探到的是端口上的任何进程,
端口被占会让基线静默打到别人身上,产出错误数据。

## 指标定义

`ksbench bench` 每轮输出一行 JSON:

| 指标 | 含义 |
|---|---|
| `rps` | 成功(ok)请求数 ÷ 实际墙钟 |
| `ttfb_us` | 非流式:响应头到达;SSE:第一个块到达 |
| `total_us` | 非流式:整个 body 读完;SSE:流关闭 |
| `sse.chunk_gap_us` | 相邻两个 SSE 块的到达间隔 |
| `ok` / `http_errors` / `transport_errors` | 分类计数,错误样本保留前 5 条 |

网关进程的 RSS 由脚本每秒采样一行(`ps -o rss`),场景起止时间戳写
`markers.log`,与 RSS 曲线对齐。

### 请求体形态(`--body-kind`)

三种形态对应 `is_stream_request` 扫描器的三条路径:

- `plain` —— 不含 `"stream"` 子串:memchr 预过滤直接否掉,不进语义扫描
- `stream_true` —— 顶层 `"stream":true`:走流式客户端(无限读超时)那条路
- `marker_in_string` —— `"stream":true` 转义后藏在字符串值里:预过滤命中,
  语义扫描必须扫到该位置才能否掉,是 tokenizer 的最坏情况

### 请求体大小(`--body-size`)

1 MB / 8 MB / 32 MB 三档;32 MB 恰好等于网关默认 `--max-body-mb`,压线通过。
改动这个数字前先对齐两侧,否则一律 413。

## 场景矩阵

按 `perf.sh` 的实际执行顺序(S1–S6 → S10 → S7 → S8 → S9):

| 场景 | 内容 |
|---|---|
| S1 直连基线 | `d/small_c8`、`d/small_c64`:1 KB echo 不经网关,并发 8 / 64 |
| S2 并发阶梯 | `g/small_c1…c256`:经网关 1 KB echo,并发 1 / 8 / 32 / 64 / 128 / 256 |
| S3 SSE | `d/g × sse_ttfb`(100×64 B,首块延迟 50 ms,c1)、`sse_long`(1000×512 B,c8)、`sse_paced`(200×512 B,8 ms 间隔,仿真 LLM 输出节奏,c8)、`sse_big`(2000×8 KB ≈ 16 MB,c2);另加 `d/g json32mb`(32 MB 非流式) |
| S4 大请求体 | `g/body_{1,8,32}MB × {plain, stream_true, marker_in_string}`;`d/body_8MB_plain` 作直连锚点 |
| S5 超并发上限 | 网关 `--max-concurrent 8` 配 64 并发客户端(`g/capped8_c64`):观察 shedding(503 + `Retry-After`)是否干净 |
| S6 审计开/关 | `g/audit_off_c32` vs `g/audit_on_c32`(c32):量化审计写入的成本 |
| S10 日志成本 | `g/logwarn_devnull_c32` / `g/loginfo_devnull_c32` / `g/loginfo_file_c32`:warn 基线 → info 格式化+写 stdout 的 CPU 成本 → 再加落盘成本。每个配置独立网关进程,防止 bind 失败后健康检查探到旧网关 |
| S7 负载下热重载 | 45 s 的 c32 负载期间做 3 次 `route add` + 2 次 mtime 扰动;断言是错误数为 0,p99 对照 `g/small_c32` |
| S8 soak | 600 s 混合负载(24 并发小请求 + 8 并发 paced SSE),配 RSS 采样:看长时间运行是否内存爬升 |
| S9 微基准 | `cargo test --release --locked perf_ -- --nocapture`:`perf_concurrent_e2e_throughput`、`perf_audit_flood_never_blocks`、`perf_route_table_10k` |

SSE 场景普遍用 `--max-requests` 限次而非只靠时长:SSE 是长连接,按时长跑
会被流占满整个采样窗,得不到足够的独立样本。

## 运行方式

```bash
cargo build --release            # perf.sh 自己也会构建,但预构建便于快速迭代
bash scripts/perf.sh             # 全量,含 600s soak
PERF_SKIP_SOAK=1 bash scripts/perf.sh   # 跳过 soak 的快速一轮
```

环境变量:`PERF_ROUNDS`(每场景轮数,默认 3)、`PERF_DURATION`(常规场景
时长,默认 15 s)、`PERF_SOAK`(soak 时长,默认 600 s)、`PERF_SKIP_SOAK=1`、
`GW_RUST_LOG`(默认 warn;info 仅供 S10)。

平台:Linux / macOS / WSL。Git Bash / MSYS2 明确不支持(无 `/dev/tcp`
端口探测,`ps` 不支持 `-o rss`),脚本会拦截并提示走 WSL。

## 结果与聚合

产物在 `perf/results/<时间戳>/`(`.gitignore` 不入库):

```
env.txt          环境(CPU/核数/内存/版本),喂给 summary 头部
rounds.jsonl     每轮一行 ksbench JSON
rss.csv          每秒一行 epoch,rss_kb
markers.log      场景起止时间戳
upstream.log / gateway.log / ksbench.err
summary.md / summary.json   聚合产物
```

`perf_aggregate.py` 只做聚合不做解读:每标签每指标取**轮间中位数**(附
rps spread =(max−min)/median,轮间抖动超过 ~20% 的场景要怀疑环境),
`d/X ↔ g/X` 成对差值表(Δttfb、Δtotal、rps 比值),RSS 的
min/first/last/peak,S7 单独一节。结论(回归判断、跨版本对比)另行归档
到 `docs/perf-report-*.md`。

轮失败、聚合失败、微基准失败任一发生,脚本以非零退出,不要只看 summary。
