# 使用指南

[← 中文 README](../../README.zh-CN.md)

路由、命令、健康检查端点以及磁盘上的保险库。服务部署见 [service.md](service.md)；威胁模型见 [security.md](security.md)。

## 路由如何工作

一个 loopback 端口服务所有路由。**请求中的 vkey 决定路由**，路由携带所有上游特定的配置：base URL、认证方式（`bearer` / `x-api-key` / 自定义 header / `basic` / query 参数）、要注入的静态 header、重试策略，以及可选的每路由上游代理。

入站的认证 header 会被剥离并根据路由重建，所以客户端无法夹带自己的凭据。其余部分（method、path、body、`Accept`、streaming）原样透传，query string 保留，仅由路由管理其中的认证参数。SSE 块到达即转发，不会缓冲成完整响应。

即使在透传模式下，也有两类请求会被直接拒绝。请求路径包含点段（`..`、`%2e%2e`，或它们的 `\` 分隔形式）会得到 404：下游 URL 解析器会折叠这些段，转发它们会让请求在上游主机上逃出路由的 base_url 前缀。`CONNECT`、`TRACE` 和 `TRACK` 会得到 405：上游实现了 TRACE 的话，会把被转发的 header（包括真实 key）原样回显给调用者。

`--auth` 只描述 keysink → 上游的方向。入站方向，vkey 可通过 `Authorization: Bearer`、`x-api-key`、`x-goog-api-key`、`api-key`、`anthropic-api-key` 或 `openai-api-key` 中的任意一种提交（转发前剥离的正是这些同名 header），所以客户端的认证方式与路由的永远不必一致。

同一端口上的两个 agent 可以分别对接两个不同的 provider，或用不同的 key 对接同一个 provider，而彼此互不知情。

## 重试

`429`/`503`/`504` 会重试两次。网络调用失败的 POST 永远不会重放，SSE streaming 一旦开始也不会重试——重放的 POST 就是账单上的第二次扣费。`--retry-on-status CODE` 替换路由的可重试状态码集合（400..=599）。

## 日常命令

```
keysink init                     # 脚本 / 无头环境中的第一个入口（交互式 serve 会自动初始化）
keysink route add|ls|show|rotate|update|rm|enable|disable
# `route rm` 会销毁仅存在于路由上的 key，所以会要求确认
# （脚本中用 `--yes`）；`route disable` 保留 key，只是停止对外服务
keysink serve [--listen 127.0.0.1:8787] [--audit-log FILE] [--max-concurrent N] [--accept-degraded]
keysink status | doctor
keysink export --output FILE      # 需要主密码；剥离所有 key 值
keysink rekey [--yes]             # 轮换保险库主密钥
keysink deploy | uninstall        # 系统级安装 / 对称移除
```

常用的 route 选项：

- `--auth bearer|x-api-key|header|basic|query|none`：OpenAI 用 Bearer，Claude 用
  `x-api-key`，Gemini 用 `x-goog-api-key`。其他情况用 `--auth header`，配合
  `--auth-header NAME` 和可选的 `--auth-prefix 'Bearer '`
- `--header 'K:V'` 注入静态 header（可重复），它是兜底而非覆盖：如果客户端发送了同名 header，客户端的值胜出。只有认证 header 的名字受保护（完全不能用静态方式设置）；把它当作路由默认值，永远不要当作强制手段；
  `--proxy URL|direct` 设置每路由的上游代理，默认取
  `HTTP(S)_PROXY`
- `--retry-on-status CODE` 按路由覆盖可重试状态码集合（400..=599）

常见操作：

```bash
keysink route update claude --base-url https://api.openai.com     # 切换上游
printf %s "$NEW_KEY" | keysink route update claude --route-key -   # 换掉真实 key
keysink route rotate claude                                       # 新 vkey，旧的立即失效
```

## Health、status、doctor

`status` 打印保险库摘要（home、schema、路由数量）。`doctor` 运行完整性检查（owner、权限、key 解析、store 解密、备份解密），当感觉不对劲时就该跑它。

要检查网关本身，`GET /__keysink/health` 返回
`{"ok":true,"healthy":true,"degraded":false,"version":"0.2.3","uptime_secs":…,"routes":2}`，
外加一些原本不可见的状态：

- `snapshot_age_secs`：当前服务的快照已存在多久。watcher 只在保险库变化时重载，所以在稳定的保险库上它会随 uptime 增长；它反映的是数据新鲜度，而不是 watcher 的健康，不要拿它做告警。
- `reload_failures` / `reload_attempts`：真正的重载信号。保险库持续损坏（比如无法解密）时 failures 会不断攀升。
- `watcher_age_secs`：store watcher 距上次 tick 的时长。
- `shed_connections` / `accept_errors`：连接上限和每连接 accept 错误的计数。
- `audit` / `audit_ok` / `audit_dropped`：audit writer 挂掉或写入失败会报告 `audit_ok:false`，而不是默默丢弃每条记录；写入路径恢复后，writer 会在空闲 tick 时探测，标志会重新打开。

`ok` 只说明进程能应答；`healthy` 说明它正在服务自己可信的数据。以下情况会变为 false：快照来自过期的备份、热重载持续失败、audit writer 无法写入，或 watcher 停止 tick。存活探针应指向 `ok`（永远不要重启一个仍在应答的网关），告警/生产就绪判断指向 `healthy`。

`--accept-degraded` 针对保险库损坏的情况：当主 store 解密失败时，网关可以从 `vault.age.bak` 启动。该备份落后一次写入，所以此后轮换或删除过的 vkey 会重新可用。这是让 agent 继续跑下去的权宜之计，不是稳态。`doctor` 会告诉你哪个文件坏了以及如何恢复。

## 保险库放在哪里

`~/.local/share/keysink`（Windows：`%LOCALAPPDATA%\keysink`；系统级安装：`/var/lib/keysink`）。用 `--home` 或 `KEYSINK_VAULT_HOME` 改变位置。

主密码只保护 `export` 备份（并且在写入之前校验）。服务、添加、轮换和禁用 key 从不要求它，所以守护进程重启不会被忘记的密码卡住。

`export` 是**配置**备份，不是可还原的保险库：它包含路由（base URL、认证方式、重试策略、vkey），所有真实 key 已剥离，所以既不能直接改名为 `vault.age` 使用，也不能解密成一个可用的保险库。恢复是手动的：用 `age -d` 解开，然后重建路由并用 `route update <name> --route-key -` 重新录入每个 key。真正能还原的是 `vault.key` + `vault.age`，备份这两个文件。

`vault.key` 是一个普通的 age identity 文件（`0600`），主密码并不保护它：保险库的保护来自文件模式加上独立 UID，所以同用户的 agent 可以离线解密它。对于服务部署，identity 可以放在保险库目录之外：`KEYSINK_MASTER_KEY`（内联 age identity）或 `KEYSINK_MASTER_KEY_FILE`（路径）；这正是 systemd 的 `LoadCredential` 想要的。

## FAQ

**为什么保险库不在当前目录？**

每个用户一个保险库，而不是每个目录一个。网关作为守护进程运行，而 CLI 可以从任意位置调用，如果保险库相对于 CWD，就意味着每个目录一个不同的保险库、路由"凭空消失"、热重载失效。加固也需要一个它完全掌控的目录：`0700`/`0600`、`O_NOFOLLOW` 和 owner 检查只在专用目录里才有意义，而 CWD 很可能是一个 git 仓库或同步文件夹，`vault.key` + `vault.age` 在那里会泄漏。这也是操作系统期望的应用数据位置（XDG `$XDG_DATA_HOME`、`%LOCALAPPDATA%`、服务用 `/var/lib`，与 `~/.ssh` 或 `/var/lib/docker` 同一约定）。想要别的位置时用 `--home` / `KEYSINK_VAULT_HOME`。

**本地代理是单点故障吗？**

它是一个本地进程，所以是的：它挂了请求就失败。`GET
/__keysink/health` 能告诉你它是否在线、是否在服务过期备份；systemd 下 unit 会在失败时重启。保险库就是普通文件，崩溃不会丢 key。

**我的 agent 收到 401——是 vkey 错了还是真实 key 错了？**

keysink 自己的 401 带有 keysink 生成的 JSON body 和 `x-keysink-request-id`
header，比如 `{"error":{"type":"authentication_error","message":"virtual key is
invalid or has been rotated …"}}`。错误的*真实* key 则来自上游：同样的状态码，但 body 是 provider 自己的错误，说明请求已被转发。
