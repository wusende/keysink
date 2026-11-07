# 发版说明（维护者）

版本号只写在 `Cargo.toml`；打 `v*` tag 后 CI 做三件事：

| Job | 产物 | 开关（仓库 Variables） |
|---|---|---|
| `build` | GitHub Release 全平台二进制 + sha256 | 无（tag 即触发） |
| `crates` | crates.io 上的 `keysink` | `CRATES_PUBLISH=true` |
| `npm` | npm 上的 `keysink` 单包 | `NPM_PUBLISH=true` |

两个发布 job 都要先手工配好 Trusted Publisher（只能由账号持有人操作），
没配之前保持变量为 false，tag 发布会跳过而不是报红。

## crates.io（`CRATES_PUBLISH`）

首次发布必须用 API token 手工完成（`cargo publish`）；Trusted Publishing
只对已存在的 crate 开放。

1. crates.io → 自己的 crate `keysink` → **Settings → Trusted Publishing → Add**
2. 平台选 **GitHub**，按下表填（字段必须与 `.github/workflows/release.yml`
   完全一致，否则 OIDC 校验失败、`crates-io-auth-action` 返回 401）：

   | 字段 | 值 |
   |---|---|
   | Repository owner | `wusende` |
   | Repository name | `keysink` |
   | Workflow filename | `release.yml` |
   | Environment | **留空** |

   - Workflow filename 只填文件名，不要 `.github/workflows/release.yml` 全路径。
   - Environment 留空是因为 workflow 里没有声明 `environment:`；
     若将来加上 `environment: release`，这里必须同步填 `release`。
   - 改了 workflow 文件名等于改了 publisher 身份，需要在 crates.io 同步改。
3. 仓库 Settings → Variables 加 `CRATES_PUBLISH = true`。

CI 的 `crates` job 会：

- 先用 tag 名和 `Cargo.toml` 的 `version` 对齐（防止 tag 是 v0.3.0、
  清单还是 0.2.2）；
- 查 `https://crates.io/api/v1/crates/keysink/<version>`，已存在就跳过，
  所以重推 tag、重跑 job 都不会因为「版本不可变」而失败；
- 通过 `rust-lang/crates-io-auth-action@v1` 用 OIDC 换 30 分钟短期 token，
  仓库里不存任何长期 token。

本地预演（不发布）：`cargo publish --dry-run --locked`。

## npm（`NPM_PUBLISH`）

细节见 `npm/README.md`，这里只列与 crates.io 对称的部分：npmjs.com →
`keysink` → Settings → Trusted publishing，Provider `GitHub Actions`，
Organization or user `wusende`，Repository `keysink`，Workflow filename
`release.yml`；随后把 Publishing access 改成
「Require two-factor authentication and disallow tokens」。

## 每次发版

```bash
# 1. 改 Cargo.toml 的 version、CHANGELOG.md 加一段 ## vX.Y.Z、
#    同步 npm/keysink/package.json 的 version（CI 会校验漂移）
# 2. 提交并推送
git tag vX.Y.Z && git push origin vX.Y.Z
```

tag 与 `Cargo.toml` 版本不一致时 `crates` job 直接失败——这是故意的：
crates.io 版本一旦上传不可撤回，宁可停在发布前。
