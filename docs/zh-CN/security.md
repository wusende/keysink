# 安全模型

[← 中文 README](../../README.zh-CN.md)

## 网关能看到什么

| 通道 | 能看到的 |
|---|---|
| `route ls` / `route show` | 掩码后的 vkey，无真实 key |
| CLI | 不存在读取命令 |
| `export` 备份 | 路由和元数据，key 值已剥离 |
| agent 进程 / env / 日志 | 只有 vkey |
| 上游 | 真实 key，转发时注入 |

保险库文件经 age 加密，`0600`/`0700`，属主为服务用户。客户端发来的
`authorization`、`x-api-key`、`x-goog-api-key`、`api-key`、`anthropic-api-key`、
`openai-api-key` 中的任意一个都会在转发前被丢弃。能同时读到 `vault.key` 和
`vault.age` 的 root 依然可以离线解密；机器级隔离仍是你自己的事（收紧 sudo、独立
UID）。在 Linux 上，`serve` 还会把自己的内存对本 uid 设为不可读
（`PR_SET_DUMPABLE = 0`，见下文），内核拒绝时会记录一条警告。

## 另外的通道：同一用户，不同进程

agent 以你的身份运行，所以它拥有你的文件权限和你的 `/proc`。
在 Linux 上以同 uid 运行 agent 和网关的实测结果：

| agent 执行的命令 | 能拿到什么 |
|---|---|
| `cat token.txt`、`.env`、`~/.config/*/credentials` | 明文——key 从来就不在保险库里 |
| `age -d -i vault.key vault.age` | 整个保险库，只要 `vault.key` 可读 |
| `tr '\0' '\n' < /proc/<pid>/environ` | 启动器注入到兄弟进程环境里的任何东西 |
| `/proc/<pid>/mem`、`gdb -p`、`strace -p` | 运行中程序的内存，包括真实 key |

前两行就是 `deploy` 的意义超出开机自启的原因：`vault.key` 是一个普通的 age
identity，文件模式对属主用户毫无保护。`deploy` 把保险库放到专用的 `keysink`
uid 下（`0700`），管理命令经 `sudo -u keysink` 执行且 `timestamp_timeout=0`，
网关也以该 uid 运行——agent 读不到其中任何东西。

后两行就是 `serve` 在启动时自我加固的原因：它在 Linux 上调用
`prctl(PR_SET_DUMPABLE, 0)`，此后同 uid 进程对
`/proc/<pid>/{environ,mem,maps}` 和 `PTRACE_ATTACH` 一律得到 `EPERM`，
无论 `kernel.yama.ptrace_scope` 是什么。必须由持有 key 的进程自己来做：
`execve(2)` 会把该标志重置为 1，所以启动器无法代劳。macOS
（`task_for_pid`）和 Windows（`SeDebugPrivilege`）本就拒绝同用户的内存读取。

在自己 uid 下独立运行的 `serve` 会让保险库文件对 agent 可读。在 agent 以你身份
运行的机器上，用 `deploy`，或换个用户运行。macOS 没有服务模式，那里的边界只能
来自 agent 的 uid。

## 审计日志

`--audit-log` 记录路由、vkey 指纹、状态码和延迟，永不记录 header、body 或
query。默认关闭。为真实流量保留五个轮换代（每代 10 MB）。被拒绝的请求被限流
（每指纹 1/s，全局 100/s）并写入自己的轮换链（`<audit-file>.rej`，
再 5 × 10 MB）；大量未认证请求只会循环覆盖自己的日志，永远不会挤掉真实流量的
记录。`serve` 在启动时验证两个文件均可追加打开，否则拒绝启动；运行时写入失败
会把 `audit_ok` 置为 false，直到路径重新可写：writer 在空闲 tick 时探测，所以
空闲的网关也能恢复，下一条记录会再次验证。

## 边界

如果坚持，`--listen` 可以绑定非 loopback 地址，但 TLS 和网络暴露就是你自己要
解决的问题了；预定的部署方式是仅 loopback。

没有任何东西是无上限的：32 MB 的 body（`--body-limit-mb`）、64 个在途请求
（`--max-concurrent`）、有上限的连接数、分阶段超时，以及 30 秒读完 http1 请求
头。非 streaming 响应 body 按块和整体双重限界，所以一个每分钟滴一个字节的
上游无法永久占住连接；一个停止应答 keep-alive PING 的 h2 连接，或在握手中
停滞的连接，会在头部超时后被关闭。挂死的上游或不守规矩的 agent 无法拖垮网关。

每个被转发的请求还有整个转发过程的预算（10 分钟）：重试次数、退避睡眠和可重试
body 的消耗共享它，所以配置了很大 `--max-retries` 的路由不能把一个入站槽位
占住几十分钟。

关闭是优雅且有界的：`serve` 停止接受新连接，通知每个存活连接完成并关闭
（`Connection: close`、h2 `GOAWAY`），在最多 `--drain-timeout-secs`
（默认 10，`0` = 永远等待）内排空，然后带一条警告丢弃剩余的。空闲的 keep-alive
socket 立即关闭，所以重启不再等满 30 秒的头部超时；systemd unit 的
`TimeoutStopSec=30` 是之上的兜底。store watcher 也受监督：死了会重启，
停止 tick 时日志会说明。
