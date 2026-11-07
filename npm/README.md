# npm 发布说明（维护者）

npm 上只有一个包：`keysink`。里面**内置了 5 个平台的二进制**，启动壳按
`process.platform` / `process.arch` 选一个执行。

```
keysink/
├── bin/keysink.js           启动壳：选平台、透传参数/信号/退出码
├── vendor/linux-x64/keysink
├── vendor/linux-arm64/keysink
├── vendor/darwin-x64/keysink
├── vendor/darwin-arm64/keysink
└── vendor/win32-x64/keysink.exe
```

## 为什么是这个形态

一开始按 esbuild 那套做了 6 个包（主包 + 5 个平台包），用户装一次要下两个包、约 7MB（主包 + 自己平台那一个）。但实际发布时：

1. npm 把这个新账号的新包转成了 `0.0.0-stage` 占位审核态，5 个包都要人工批；
2. `keysink-win32-x64` 这个**包名**被反垃圾规则直接 403（同类案例 `keelrun-cli-win32-x64`，结论是必须提工单，重试无效）。

改成「单包 + 安装时从 GitHub 下载」能绕开这两个问题，但把最不可达的一环放到了安装路径上：
npm registry 有 npmmirror 等完整镜像，GitHub Releases 没有，国内用户安装大概率超时。

所以最终形态是**单包内置全部二进制**：

| 指标 | 数值 |
|---|---|
| tarball | ~16.6 MB |
| 解压后 | ~39 MB（registry 的 `unpackedSize`，2026-11 实测） |
| 安装时网络 | 只需 npm registry（可走镜像） |
| postinstall | 无 |
| `--ignore-scripts` | 不受影响 |

代价是每个用户都为 5 个平台付流量（实际只用其中一个）；换来的是装包即用、不联网、不跑脚本。

## 一次性准备（只有账号持有人能做）

1. **npm 账号 + 邮箱验证**，**开 2FA**。
2. **首次手工发布**：

   ```bash
   # 本机需要代理拉 GitHub 资产；CI 不需要。用你自己的代理地址
   export HTTPS_PROXY=http://127.0.0.1:7890
   bash scripts/npm-pack.sh            # 从 GitHub Releases 拉 5 个资产并校验 sha256
   bash scripts/npm-publish.sh --dry-run
   bash scripts/npm-publish.sh --otp 123456
   ```

   注意：如果账号仍处于「新发布者审核」状态，`npm publish` 可能又生成 `0.0.0-stage`
   占位包，需要去 npmjs.com 的 **Staged Packages** 批准，或提工单。

3. **给 `keysink` 配 Trusted Publisher**（npmjs.com → 包 → Settings → Trusted publishing；crates.io 的同名配置见 `docs/publishing.md`）：

   | 字段 | 值 |
   |---|---|
   | Provider | GitHub Actions |
   | Organization or user | `wusende` |
   | Repository | `keysink` |
   | Workflow filename | `release.yml` |

   然后把 Publishing access 改成「Require two-factor authentication and disallow tokens」。

4. **打开 CI 自动发布**：仓库 Settings → Variables 加 `NPM_PUBLISH = true`。

5. **清理早期占位包**（6 包方案留下的，与本方案无关）：

   ```bash
   for p in keysink-linux-x64 keysink-linux-arm64 keysink-darwin-x64 keysink-darwin-arm64; do
     npm unpublish "$p" --force || true   # 没发成功过的包会报 404，忽略
   done
   ```

## 每次发版

版本号只写在 `Cargo.toml`，`npm-pack.sh` 会同步进 `npm/keysink/package.json`；
`npm/keysink/package.json` 是入库文件，所以**发版提交必须把它一起改掉**——CI 的
`npm manifest matches Cargo.toml` 步骤会拦截漂移（本地可先跑
`bash scripts/npm-pack.sh --check-version`）。

```bash
# 1. 改 Cargo.toml 版本 + CHANGELOG + npm/keysink/package.json 的 version，提交
# 2. 打 tag → CI 构建五平台，再打包成单包发布 npm（NPM_PUBLISH=true 时）
git tag v0.1.4 && git push origin v0.1.4
```

CI 里的 npm job 用构建产物（`--from-artifacts`）而不是从 GitHub 下载，避免依赖 Release
上传完成的时序。手动补发：`bash scripts/npm-pack.sh --from-release && bash scripts/npm-publish.sh`。

本地只想验证启动壳：

```bash
bash scripts/npm-pack.sh --from-target   # 只 stage 本机已构建的平台
npm install -g ./npm/dist/keysink
keysink --version
```

## 平台矩阵

| vendor 目录 | Rust target | 运行要求 |
|---|---|---|
| `linux-x64` | `x86_64-unknown-linux-gnu` | glibc 2.35+（在 ubuntu-22.04 上构建） |
| `linux-arm64` | `aarch64-unknown-linux-gnu` | glibc 2.39+（arm64 runner 只有 24.04） |
| `darwin-x64` | `x86_64-apple-darwin` | macOS 11+ |
| `darwin-arm64` | `aarch64-apple-darwin` | Apple Silicon |
| `win32-x64` | `x86_64-pc-windows-msvc` | Windows 10+ |

没覆盖的平台（musl/Alpine、Windows arm64）由启动壳给出明确提示并回退到 `cargo install`。
要补 musl，加 `x86_64-unknown-linux-musl` 构建 + `vendor/linux-x64-musl`，并在启动壳里按
`process.report` 的 `glibcVersionRuntime` 分支。

## 文件

- `npm/keysink/` — 启动壳与清单（唯一提交的 package.json）
- `scripts/npm-pack.sh` — 拉资产、校验 sha256、解包进 `npm/dist/keysink/vendor/**`
- `scripts/npm-publish.sh` — 发布单包；已发布的版本自动跳过，2FA 码过期可直接重跑
