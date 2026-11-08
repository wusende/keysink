# 性能

[← 中文 README](../../README.zh-CN.md)

一台机器上的参考数字（Apple M4 Pro、macOS 26、v0.2.2 的 release 构建；loopback
上的 1 KB POST，每次运行 10 秒）——把它们当作数量级参考，并用测试脚本在你自己的
硬件上复现：

| 场景 | 直连 | 经 keysink |
|---|---|---|
| 1 KB echo，并发 8 | 102k rps · p50 75 µs · p99 136 µs | 51k rps · p50 153 µs · p99 238 µs |
| 1 KB echo，并发 64 | — | 80k rps · p50 785 µs · p99 1.4 ms |
| SSE 首块延迟（上游等待 50 ms） | p50 52.4 ms | p50 52.7 ms（+0.3 ms） |
| SSE 块间隔（p50） | 0 µs | 4 µs |

两次额外的 loopback 跳数在微型请求上消耗真实吞吐量——相同并发下大约减半，p50
约 80 µs。对于一个几百毫秒才应答、持续流式输出数秒的 LLM 上游来说，两者都是
噪音。

`scripts/perf.sh` 是完整的测试脚本：并发阶梯、三种 `stream` 标记形态、最大
32 MB 的请求体、最大 16 MB 的 SSE 流、并发上限下的行为、audit 开/关、单请求
日志开销、负载下的热重载，以及带 RSS 采样的 10 分钟 soak。方法论与指标定义见
[perf-test-plan.md](perf-test-plan.md)。
