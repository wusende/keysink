# keysink

[English](README.md) | 简体中文

[![CI](https://github.com/wusende/keysink/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/keysink/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keysink.svg)](https://crates.io/crates/keysink)
[![docs.rs](https://img.shields.io/docsrs/keysink)](https://docs.rs/keysink)
[![Release](https://img.shields.io/github/v/release/wusende/keysink)](https://github.com/wusende/keysink/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/wusende/keysink/releases/latest)

> 1.0 之前,CLI 与路由接口仍可能在版本间变动;每个版本的操作注意事项见 [CHANGELOG](CHANGELOG.md)。

一个本地小网关,把你的真 API key 留在 agent 之外。agent 手里只有可吊销的虚拟 key(`ks_…`);真 key 加密存在本地保险库里,只在转发那一刻替换进去。

```
agent ──ks_…──▶ keysink :8787 ──真 key──▶ 上游
```

## 这个工具针对的威胁

agent 整天在读不可信的内容:网页、issue 讨论、工具输出、抓取的文档。离一次 prompt 注入的距离,`env | curl …` 就能把你的真 key 送出门,而你往往是从账单上知道的。

真 key **没有任何读取通道**:CLI 打印不出来,`export` 备份会剥离,网关只绑 loopback。被 dump 出来的环境里只有一把 `ks_…`——一条命令吊销,其余一切照常。

一把真 key 可以支撑多条路由:每个 agent 拿自己的 `ks_…`,换 key 或换供应商就是 `keysink route update`,路由热重载约 1 秒,agent 配置只写这一次。

### 其它通道

agent 是用你的账号跑的,它也就有你的文件和 `/proc`。Linux 上同 uid 实测:

| agent 执行 | 拿到什么 |
|---|---|
| `cat token.txt`、`.env`、`~/.config/*/credentials` | 明文——这把 key 从来没进过保险库 |
| `age -d -i vault.key vault.age` | 整个保险库(只要 `vault.key` 可读) |
| `tr '\0' '\n' < /proc/<pid>/environ` | 启动器注入给别的进程的全部明文 |
| `/proc/<pid>/mem`、`gdb -p`、`strace -p` | 运行中进程的内存,里面就是真 key |

前两行靠 `deploy` 给出的独立 uid 堵上;后两行靠 `serve` 在 Linux 上的 `prctl(PR_SET_DUMPABLE, 0)`(同 uid 读 `/proc/<pid>/*`、`ptrace` 全变 `EPERM`)。两者都在你自己的 uid 里跑时,这些都挡不住——保险库文件就是共享的。细节和做法见
[docs/zh-CN/security.md](docs/zh-CN/security.md)。

## 快速开始

1. 安装,任选一种:

   ```bash
   npm install -g keysink     # 预编译二进制,不需要工具链
   cargo install keysink      # 从 crates.io 编译,需要 Rust 工具链
   ```

   `cargo install` 装到 `~/.cargo/bin`,sudo 看不到这个目录。所以后面要跑 `sudo keysink deploy` 时,写成 `sudo ~/.cargo/bin/keysink deploy`。也可以从 [Releases](https://github.com/wusende/keysink/releases) 下对应平台的二进制放进 `PATH`;Linux x86_64 需要 glibc 2.35+,arm64 需要 2.39+,没覆盖到的平台(musl/Alpine、Windows arm64)回退到 `cargo install`。

2. 启动网关(standalone,无需 root、无需装服务):

   ```bash
   keysink serve      # 首次运行会交互式初始化(设主密码),然后网关启动
   ```

3. 另开一个终端加路由:

   ```bash
   keysink route add claude --base-url https://api.anthropic.com
   # 引导式提问:名称 → base URL → 上游鉴权方式 → key(隐藏输入)
   # 非交互:printf %s "$KEY" | keysink route add claude --base-url … --auth x-api-key
   ```

   它会打印 vkey(只显示这一次)和 agent 需要的那两行:

   ```
   vkey: ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
     BASE_URL=http://127.0.0.1:8787
     TOKEN=ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
   ```

   路由热重载进运行中的网关大约 1 秒,加路由不需要重启。

4. 把 agent 指过来:Claude Code 在 `settings.json` 里用 `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`,其它客户端用 provider 的 `base_url` + `apiKey`(OpenAI 兼容客户端通常要在 base URL 末尾加 `/v1`)。vkey 走的就是客户端本来就在发的那个头,所以对多数客户端来说,这只是一次 base URL 改动。

## 文档

| 文档 | 内容 |
|---|---|
| [usage.md](docs/zh-CN/usage.md) | 路由规则、全部命令与路由选项、health endpoint 字段、保险库布局、FAQ |
| [service.md](docs/zh-CN/service.md) | `sudo keysink deploy`:系统用户、systemd unit、无终端初始化 |
| [security.md](docs/zh-CN/security.md) | 威胁模型、同 uid 通道、审计日志、各种上界与关闭流程 |
| [performance.md](docs/zh-CN/performance.md) | 实测开销与 `scripts/perf.sh` 压测工具 |

英文原文见 [docs/](docs/)。

## 它不是什么

- 不是 secret manager:单用户,没有 RBAC、HA、KMS。多人或多机共享要用 Vault、Infisical 或云厂商的 secrets manager。
- 不是 LLM 网关:不做 token 计费、预算、模型路由、缓存、限流。要这些就配 LiteLLM / one-api。
- 不是多机方案:一个进程、一台机器、loopback。
- 不做 key 池:一条路由一个上游一把 key,没有故障转移。
- 不是 agent 的沙箱:vkey 就是能力,收回靠 `route disable` / `rotate`。
- 如果你的 agent 从不接触不可信内容,多这一跳不值:普通 `.env` 更简单,而且它同样挡不住同事。

## 开发

```bash
cargo test
cargo build --release
bash scripts/smoke.sh    # 端到端:假上游、转发 / SSE / 重试 / 热重载 / export 剥离
```

`cargo test` 含一套带种子的 fuzz(22 个目标覆盖纯函数、保险库损坏矩阵,以及对假上游的端到端 fuzz)和 `perf/ksbench` 压测。推 `v*` tag 会让 GitHub Actions 构建并发布各平台产物;`CRATES_PUBLISH` / `NPM_PUBLISH` 打开后同时发 crates.io 和 npm(见 `docs/publishing.md`)。

---

如果 keysink 让你不用再往 agent 配置里贴 API key——或者它已经替你省下一次轮换——去 [点个 star](https://github.com/wusende/keysink/stargazers),让下一个人在泄漏之前看到它。给非 agent 场景的文件态密钥,看同作者的 [envpouch](https://github.com/wusende/envpouch):加密的 `.env` profile。
