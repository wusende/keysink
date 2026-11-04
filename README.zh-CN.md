# keysink

[English](README.md) | 简体中文

[![CI](https://github.com/wusende/keysink/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/keysink/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keysink.svg)](https://crates.io/crates/keysink)
[![Release](https://img.shields.io/github/v/release/wusende/keysink)](https://github.com/wusende/keysink/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

本机小型网关:真 API key 不进 agent。agent 只拿到可随时吊销的虚拟 key(`ks_…`),真 key 加密存在本地保险库,只在转发那一刻替换进去。

```
agent ──ks_…──▶ keysink :8787 ──真 key──▶ 上游
```

真 key **没有任何读取通道**:CLI 打印不出来,`export` 备份会剥离,网关只绑 loopback。

## 为什么值得装

**换 key 不用碰 agent。** agent 配置里只写一次 base URL 和那个 `ks_…` token。之后换供应商、换账号、换真 key,都是 `keysink route update` 一句话的事——路由热重载进运行中的网关,大约 1 秒。不改配置、不重启 agent。

**一个真 key,拆成多个可独立吊销的虚拟 key。** 每个 agent 一条路由:同一个上游,各自的 vkey,各管各的。吊销或停用其中一个,其余照常。

**重试不会重复扣费。** `429`/`503`/`504` 重试两次,但**网络层失败的 POST 绝不重放**,SSE 一旦开始流式输出就不再重试。一次重放就是账单上多一笔。

名字就是这件事:被 prompt 注入的 agent 能把环境里的东西全吐出来,而真 key 从来不在里面。

## 快速开始

1. 安装,任选一种:

   ```bash
   npm install -g keysink     # 预编译二进制,不需要工具链
   cargo install keysink      # 从 crates.io 编译,需要 Rust 工具链
   ```

   `cargo install` 装到 `~/.cargo/bin`,sudo 看不到这个目录。所以后面要跑 `sudo keysink deploy` 时,写成 `sudo ~/.cargo/bin/keysink deploy`。

   也可以从 [Releases](https://github.com/wusende/keysink/releases) 下载对应平台的二进制——Linux / macOS / Windows,amd64 / arm64——加执行权限放进 `PATH`。npm 包只是同一个二进制的启动壳;Linux x86_64 需要 glibc 2.35+,arm64 需要 2.39+,没覆盖到的平台(musl/Alpine、Windows arm64)请回退到 `cargo install`。

2. 启动网关(standalone 模式,无需 root、无需装服务):

   ```bash
   keysink serve
   # 首次运行会交互式初始化(设主密码),然后网关启动
   ```

3. 另开一个终端加路由:

   ```bash
   keysink route add claude --base-url https://api.anthropic.com
   # 引导式提问:名称 → base URL → 上游鉴权方式 → key(隐藏输入)
   # 非交互:printf %s "$KEY" | keysink route add claude --base-url … --auth x-api-key
   ```

   它会打印 vkey 和 agent 需要的那两行:

   ```
   route `claude` created (key goes in, never out: cannot be read/exported)
   auth: x-api-key    base_url: https://api.anthropic.com
   vkey: ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
   (vkey is shown only this once; if lost, only `keysink route rotate claude` can issue a new one)
   gateway: http://127.0.0.1:8787 (running)
   agent-side config (OpenAI-compatible clients usually need /v1 in base_url):
     BASE_URL=http://127.0.0.1:8787
     TOKEN=ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
   ```

   路由热重载进运行中的网关,大约 1 秒,加路由不需要重启。

4. 把 agent 指过来:

   ```
   BASE_URL=http://127.0.0.1:8787
   TOKEN=ks_...
   ```

   Claude Code:`settings.json` 里 `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`。其它客户端:provider 的 `base_url` + `apiKey`。

   vkey 走的就是客户端本来就在发的那个头——`Authorization: Bearer`、`x-api-key`、`x-goog-api-key` 或 `api-key`——所以对多数客户端来说,这只是一次 base URL 改动。

## 路由是怎么走的

一个 loopback 端口服务所有路由。**请求里的 vkey 决定走哪条路由**,而路由上挂着所有跟上游相关的东西:base URL、鉴权方式(`bearer` / `x-api-key` / 自定义 header / `basic` / query 参数)、要注入的静态 header、重试策略,以及可选的单路由上游代理。

客户端发来的鉴权头会被剥掉、按路由重建,所以客户端没法夹带自己的凭证。其余原样透传:方法、路径、body、`Accept`、流式响应,query string 也保留(鉴权参数由路由管理)。SSE 按块转发,不会把整个响应缓冲起来。

透传有两条网关自己拦下的边界:请求路径里出现点段(`..`、`%2e%2e`,含 `\` 分隔的变体)一律 404——下游的 URL 解析器会把它们归一化掉,放行等于允许请求逃出 base_url 前缀、打上游主机任意路径;`CONNECT`/`TRACE`/`TRACK` 一律 405——上游若实现了 TRACE,回显的正是注入后的真 key。

`--auth` 只管 keysink → 上游这一段。入站方向,vkey 落在 `Authorization: Bearer`、`x-api-key`、`x-goog-api-key`、`api-key`、`anthropic-api-key`、`openai-api-key` 任一个头里都能认出来(与转发前剥离的名单一致),所以客户端的鉴权方式和路由的鉴权方式不需要一致。

同一个端口上的两个 agent,可以打两个不同的供应商,也可以打同一个供应商但用不同的真 key,彼此都不用知道。

## 日常命令

```
keysink init                     # 脚本/无终端环境的首次入口(交互终端里 serve 会自动初始化)
keysink route add|ls|show|rotate|update|rm|enable|disable
keysink serve [--listen 127.0.0.1:8787] [--audit-log FILE] [--max-concurrent N] [--accept-degraded]
keysink status | doctor
keysink export --output FILE      # 需要主密码;剥离所有 key 值
keysink rekey [--yes]             # 轮换保险库主密钥
keysink deploy | uninstall        # 系统安装 / 对称卸载
```

值得知道的路由选项:

- `--auth bearer|x-api-key|header|basic|query|none`——OpenAI 是 Bearer,Claude 是 `x-api-key`,Gemini 是 `x-goog-api-key`。其它情况用 `--auth header` 配 `--auth-header 名字`,需要前缀再加 `--auth-prefix 'Bearer '`
- `--header 'K:V'` 注入静态 header(可重复)——是兜底不是强制:客户端发了同名 header 时以客户端的值为准;auth 名单里的头是唯一例外(它们根本不允许配成静态 header)。把它当路由默认值用,别当强制策略用;`--proxy URL|direct` 设单路由上游代理,默认跟随 `HTTP(S)_PROXY`
- `--retry-on-status CODE` 按路由覆盖可重试的状态码集合(400..=599)

常用的几个动作:

```bash
keysink route update claude --base-url https://api.openai.com     # 换上游
printf %s "$NEW_KEY" | keysink route update claude --route-key -   # 换真 key
keysink route rotate claude                                       # 换 vkey,旧的立即失效
```

`status` 打印保险库摘要(位置、schema、路由数)。`doctor` 跑完整性检查——属主、权限、key 能否解析、store 能否解密、备份能否解密——出问题先跑它。

要确认网关本身活着,用 `GET /__keysink/health`,返回 `{"ok":true,"degraded":false,"version":"0.2.0","uptime_secs":…,"routes":2}`;另外还有以前看不见的状态:`snapshot_age_secs`(当前快照已服务多久——监听器只在保险库变更时才重载,保险库稳定不变时它会随 uptime 正常增长,反映的是数据新旧而不是监听器健康,别拿它做告警)、`reload_failures` / `reload_attempts`(真正的重载信号:保险库一直坏着时 failures 会持续上涨)、`shed_connections` / `accept_errors`(连接上限丢弃数、每连接 accept 错误数),以及 `audit` / `audit_ok` / `audit_dropped`(审计写线程死掉时 `audit_ok:false`,而不是默默丢每一行)。

`--accept-degraded` 是保险库坏了时的逃生口:主 store 解密失败时,允许网关改用 `vault.age.bak` 启动。那份备份落后一次写入,所以这段时间里被轮换或删除的 vkey 会重新生效——它只是让 agent 继续跑,不是可以长待的状态。`doctor` 会告诉你哪个文件坏了、怎么恢复。

## 保险库在哪

`~/.local/share/keysink`(Windows:`%LOCALAPPDATA%\keysink`;系统安装:`/var/lib/keysink`)。用 `--home` 或 `KEYSINK_VAULT_HOME` 换位置。

主密码只用于加密和恢复 `export` 备份——服务、加 key、轮换、停用都不问主密码,所以忘了密码不会卡住守护进程重启。

`vault.key` 是明文的 age identity 文件(`0600`),并不由主密码保护:保险库的防护是文件权限加独立 UID。服务态可以把 identity 放到保险库目录外面——`KEYSINK_MASTER_KEY`(直接给 age identity)或 `KEYSINK_MASTER_KEY_FILE`(给一个文件路径),systemd 的 `LoadCredential` 要的就是这种。

## Linux 系统服务

```bash
sudo keysink deploy
```

一条命令:创建 `keysink` 系统用户和 0700 保险库目录,把二进制装到 `/usr/local/bin/keysink`,写好 systemd unit 和 sudoers 规则(给执行 sudo 的管理员),交互式初始化保险库(隐藏输入、输两遍),然后启用服务。幂等——重复执行就是原地升级并重启。卸载对称:`sudo keysink uninstall`。

unit 在保险库不存在时拒绝启动(`ConditionPathExists`)。部署主机上没有终端时,手动初始化——有 tty 的交互式:

```bash
sudo -u keysink /usr/local/bin/keysink --home /var/lib/keysink init
```

完全没有 tty 时(`init` 不会在无终端时提示输入,必须走 stdin):

```bash
printf '%s\n' "$MASTER_PASSWORD" | sudo -u keysink /usr/local/bin/keysink \
  --home /var/lib/keysink init --password-stdin
```

之后管理命令走 `sudo -u keysink /usr/local/bin/keysink …`,每次调用都重新鉴权(`timestamp_timeout=0`),agent 没法静默执行。

## 安全模型

| 通道 | 能看到什么 |
|---|---|
| `route ls` / `route show` | 打码的 vkey,没有真 key |
| CLI | 不存在读取命令 |
| `export` 备份 | 路由和元数据,key 值被剥离 |
| agent 进程 / 环境变量 / 日志 | 只有 vkey |
| 上游 | 真 key,在转发时注入 |

保险库文件是 age 加密的,`0600`/`0700`,属主是服务用户。能同时读到 `vault.key` 和 `vault.age` 的 root 仍然可以离线解密——机器级隔离仍然是你的事(收紧 sudo、独立 UID)。

客户端发来的 `authorization`、`x-api-key`、`x-goog-api-key`、`api-key`、`anthropic-api-key`、`openai-api-key` 都会在转发前丢弃。

`--audit-log` 记录路由、vkey 指纹、状态码和延迟——不记 header、body、query。默认关闭。真实流量保留 5 份轮转日志(每份 10 MB)。被拒的请求单独写进自己的轮转链(`<审计文件>.rej`,同样 5 × 10 MB),并按指纹每秒 1 条、全局每秒 100 条节流——未鉴权的请求洪水最多逐出拒绝记录自己的历史,动不了真实流量的取证记录。

`--listen` 可以绑非 loopback 地址,但那样 TLS 和网络暴露面就得你自己解决;预期部署方式只有 loopback。请求的每个环节默认都有上界——body 大小、并发数、连接数、时间——上游挂死或 agent 失常不会拖垮网关。非流式响应体既按单块也按整体设上界,所以一分钟吐一个字节的上游也没法永久占住连接。空闲连接也有界:http1 的 head 必须在 30 秒内发完,h2 连接如果不再回应 keep-alive PING 会被关掉。

关闭是优雅且有界的:`serve` 停止接受新连接,通知每条活着的连接处理完当前响应后关闭(`Connection: close`,h2 发 `GOAWAY`),最多 drain `--drain-timeout-secs`(默认 10,`0` 表示一直等),到点还在的连打一行 warning 后丢弃。空闲 keep-alive 连接会立即关闭,重启不用再等 30 秒的 head 超时;systemd unit 里的 `TimeoutStopSec=30` 是更上一层的兜底。store 监听器也加了看门狗:死了会重启,停止 tick 会在日志里报出来。

## 它不是什么

- 不是 secret manager:单用户,没有 RBAC、HA、KMS 集成。
- 不是 LLM 网关:不做 token 计量、预算、模型路由、缓存、限流。要这些,把 LiteLLM 或 one-api 放在它旁边。
- 不是多机方案:一个进程、一台机器、loopback。
- 不是 key 池:一条路由一个上游一个 key,没有 failover。
- 不是 agent 沙箱:vkey 本身就是能力凭证,收权靠 `route disable` / `rotate`。

## 常见问题

**为什么保险库不放在当前目录?**

一个用户一个保险库,不是一个目录一个:网关作为守护进程跑,CLI 从任何地方调用,CWD 相对路径会让每个目录一个库、路由凭空消失、热重载坏掉。而且 `0700`/`0600`、`O_NOFOLLOW`、属主校验只有在专用目录里才有意义——CWD 权限随意,很可能还是 git 仓库或同步盘,`vault.key` + `vault.age` 会漏出去。这也是系统期望应用数据待的地方(XDG `$XDG_DATA_HOME`、`%LOCALAPPDATA%`、服务的 `/var/lib`,和 `~/.ssh`、`/var/lib/docker` 一个约定)。确实想换位置就用 `--home` / `KEYSINK_VAULT_HOME`。

**本地代理岂不是单点故障?**

是个本地进程,所以是的——它挂了请求就失败。`GET /__keysink/health` 能看出它活着没有、是不是在用落后一份的备份;systemd 下 unit 失败会自动重启。保险库是普通文件,进程崩了不会丢 key。

**agent 报 401,是 vkey 错还是真 key 错?**

keysink 自己回的 401,body 是 keysink 的 JSON,响应头带 `x-keysink-request-id`,例如 `{"error":{"type":"authentication_error","message":"virtual key is invalid or has been rotated …"}}`。真 key 错则是上游回的——状态码一样,但 body 是供应商自己的错误格式,说明请求已经转发出去了。

## 开发

```bash
cargo test
cargo build --release
bash scripts/smoke.sh    # 端到端:假上游、转发 / SSE / 重试 / 热重载 / 导出剥离
```

`cargo test` 里带一套固定种子的 fuzz(22 个纯函数目标、保险库损坏矩阵、对着 mock 上游的端到端 fuzz),外加带预算的性能场景。推 `v*` tag 会触发 GitHub Actions 构建并发布全平台产物,开了 `NPM_PUBLISH` 后同时发布 npm 包——见 `npm/README.md`。
