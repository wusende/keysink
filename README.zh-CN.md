# keysink

[English](README.md) | 简体中文

[![CI](https://github.com/wusende/keysink/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/keysink/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keysink.svg)](https://crates.io/crates/keysink)
[![Release](https://img.shields.io/github/v/release/wusende/keysink)](https://github.com/wusende/keysink/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

本地小型凭证网关:让真 API key 远离你的 agent。agent 只持有可随时吊销的虚拟 key(`ks_...`),keysink 把真 key 加密存在本机,仅在转发请求时注入上游。

真 key **没有任何读取通道**:CLI 打印不出、备份导出会剥离、网关只绑 loopback。

## 快速开始

1. 安装——二选一:

   ```bash
   cargo install keysink      # 从 crates.io 编译安装(需要 Rust 工具链)
   ```

   或者从 [Releases](https://github.com/wusende/keysink/releases) 下载对应平台的二进制——Linux / macOS / Windows,amd64 / arm64。加执行权限并放进 `PATH`。

2. 启动网关(standalone 模式,无需 root、无需装服务):

   ```bash
   keysink serve
   # 首次运行:交互初始化(设置 master password),然后网关启动
   ```

3. 添加路由(另开一个终端):

   ```bash
   keysink route add claude --base-url https://api.anthropic.com
   # 引导式输入:名称 → base URL → 上游认证方式 → key(隐藏回显)
   # 非交互:printf %s "$KEY" | keysink route add claude --base-url ... --auth x-api-key
   ```

   `route add` 结束时打印 agent 需要的两行配置。路由改动约 1s 内热加载进运行中的网关。

4. 把 agent 指向网关:

   ```
   BASE_URL=http://127.0.0.1:8787
   TOKEN=ks_...
   ```

   Claude Code:在 `settings.json` 里配 `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`。其他客户端:provider 的 `base_url` + `apiKey`。

vault 落在 `~/.local/share/keysink`(Windows:`%LOCALAPPDATA%\keysink`),可用 `--home` 或 `KEYSINK_VAULT_HOME` 换位置。master password 只用于 `export` 备份的加密与恢复——serve、加 key、轮换都不需要它。

## Linux 系统服务(systemd)

```bash
sudo keysink deploy
```

一键完成——二进制自己安装自己:创建 `keysink` 系统用户与 0700 vault 目录、把当前二进制装到 `/usr/local/bin/keysink`、写 systemd unit 与 sudoers(放行发起 sudo 的管理员)、交互初始化 vault(密码隐藏回显两遍)、启用服务。幂等,重复执行即原地升级并重启。卸载对称:`sudo keysink uninstall`。

vault 未初始化时 unit 不启动(`ConditionPathExists`)。无终端环境手动初始化:

```bash
runuser -u keysink -- /usr/local/bin/keysink --home /var/lib/keysink init
```

此后管理命令走 `sudo -u keysink keysink ...`;sudoers 每条重新认证(`timestamp_timeout=0`),agent 无法自动执行管理命令。

## 日常命令

```
keysink route add|ls|show|rotate|update|rm|enable|disable
keysink serve [--listen 127.0.0.1:8787] [--audit-log FILE]
keysink status | doctor
keysink export --output FILE      # 需 master password;剥离所有 key 值
keysink rekey [--yes]             # 更换 vault 主密钥
keysink uninstall [--yes]         # 删除 vault;系统级部署同时移除 unit/sudoers/二进制
keysink deploy                    # 一键系统级部署(Linux + systemd,需 sudo)
```

路由选项要点:

- `--auth bearer|x-api-key|<自定义 header>|basic|query|none`——OpenAI 用 Bearer,Claude 用 `x-api-key`,Gemini 用 `x-goog-api-key`
- `--header 'K:V'` 注入静态头;`--proxy URL|direct` 按路由设置上游代理(默认跟随 `HTTP(S)_PROXY`)
- 429/503/504 重试 2 次;POST 网络错误不重放(防重复计费);SSE 开始转发后不再重试

## 安全模型:key 只进不出

| 通道 | key 值 |
|---|---|
| `route ls` / `route show` | 打码 |
| CLI 读取命令 | 不存在 |
| `export` 备份 | 刻意剥离 |
| agent 进程 | 只接触 vkey |
| 上游 | 转发时注入真 key;入站认证头一律剥离 |

vault 文件 age 加密,0600/0700,属主为服务用户。能同时读到 `vault.key` 和 `vault.age` 的 root 仍可离线解密——机器级隔离要靠自己(收紧 sudo、独立 UID)。可选的 `--audit-log` 记录 route、vkey 指纹、状态与耗时,绝不记录 header、body、query。

限制:单路由单上游单 key(无 key 池 / failover);审计默认关闭。

## 常见问题

**为什么 vault 不放在当前目录?**

vault 固定落在 `~/.local/share/keysink`(Windows:`%LOCALAPPDATA%\keysink`,系统部署:`/var/lib/keysink`),是有意的:

- **一个用户一个 vault,而不是一个目录一个。** 网关是常驻进程,CLI 却可能从任何目录调用;若跟着当前目录走,每个目录一份 vault——路由"加丢了"、热加载也失灵。要换位置用 `--home` 或 `KEYSINK_VAULT_HOME` 显式指定。
- **安全模型要求目录本身可控。** 0700/0600、`O_NOFOLLOW`、属主跟随这些检查,只有在专属目录里才有意义;当前目录权限任意,还可能是 git 仓库或网盘同步目录,`vault.key` + `vault.age` 手滑提交/同步出去就泄了。
- **这就是操作系统给应用数据规定的位置。** Linux/macOS 按 XDG 放 `$XDG_DATA_HOME`,Windows 放 `%LOCALAPPDATA%`,系统服务按 FHS 放 `/var/lib`——和 `~/.ssh`、`~/.gnupg`、`/var/lib/docker` 是同一套约定。

## 开发

```bash
cargo test
cargo build --release
bash scripts/smoke.sh    # 端到端:本地假上游,覆盖转发 / SSE / 重试 / 热加载 / 导出剥离
```

推送 `v*` tag 后 GitHub Actions 自动构建并发布全平台 release 产物。
