# Performance

[← README](../README.md)

One machine's reference numbers (Apple M4 Pro, macOS 26, release build of
v0.2.2; 1 KB POST over loopback, 10-second runs) — treat them as order of
magnitude and reproduce with the harness on your own hardware:

| scenario | direct | through keysink |
|---|---|---|
| 1 KB echo, concurrency 8 | 102k rps · p50 75 µs · p99 136 µs | 51k rps · p50 153 µs · p99 238 µs |
| 1 KB echo, concurrency 64 | — | 80k rps · p50 785 µs · p99 1.4 ms |
| SSE time-to-first-chunk (upstream waits 50 ms) | p50 52.4 ms | p50 52.7 ms (+0.3 ms) |
| SSE inter-chunk gap (p50) | 0 µs | 4 µs |

The two extra loopback hops cost real throughput on tiny requests — roughly
half at the same concurrency, about 80 µs at p50. Against an LLM upstream that
answers in hundreds of milliseconds and streams for seconds, both are noise.

`scripts/perf.sh` is the full harness: a concurrency ladder, request bodies up
to 32 MB in three `stream`-marker shapes, SSE streams up to 16 MB, behavior at
the concurrency cap, audit on/off, per-request log cost, hot reload under load,
and a 10-minute soak with RSS sampling. Methodology and metric definitions:
[perf-test-plan.md](perf-test-plan.md).
