#!/usr/bin/env bash
# 安装 keysink：建 keysink 用户 / 装二进制 / unit / sudoers / 交互初始化 vault。
# 先读一遍再跑；需要 root。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HUMAN="${SUDO_USER:-ares}"
VAULT_HOME="/var/lib/keysink"
BIN_DIR="/usr/local/bin"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行：sudo bash contrib/deploy.sh" >&2
  exit 1
fi

if [[ ! -x "$ROOT/target/release/keysink" ]]; then
  echo "先构建：cd $ROOT && eval \"\$(clashctl env)\" && cargo build --release" >&2
  exit 1
fi

id keysink >/dev/null 2>&1 || \
  useradd --system --home-dir "$VAULT_HOME" --shell /usr/sbin/nologin keysink

install -d -o keysink -g keysink -m 0700 "$VAULT_HOME"
install -m 0755 "$ROOT/target/release/keysink" "$BIN_DIR/keysink"
# 旧版双二进制部署的残留，清掉
rm -f "$BIN_DIR/keysink-admin" /etc/sudoers.d/keysink-admin

# 初始化 vault：master password 由用户当场输入（隐藏回显、输两遍）。
# 该密码只用于 export 备份的加密与恢复；写入/轮换/serve 都不需要它。
# --home 必须显式：vault.key 还不存在时，默认目录探测会回落到用户自己的
# standalone 目录，runuser 的 HOME 漂移会把首次 init 写进错误位置。
if [[ ! -f "$VAULT_HOME/vault.key" ]]; then
  if [[ -t 0 ]]; then
    echo "==> 初始化 vault（设置 master password，只用于备份导出/恢复）"
    runuser -u keysink -- "$BIN_DIR/keysink" --home "$VAULT_HOME" init
  else
    echo "vault 尚未初始化，且当前无终端；请手动执行：" >&2
    echo "  runuser -u keysink -- $BIN_DIR/keysink --home $VAULT_HOME init" >&2
  fi
fi

install -m 0644 "$ROOT/contrib/keysink.service" /etc/systemd/system/keysink.service
sed "s/^ares /$HUMAN /" "$ROOT/contrib/keysink.sudoers" > /etc/sudoers.d/keysink
chmod 0440 /etc/sudoers.d/keysink
visudo -cf /etc/sudoers.d/keysink >/dev/null

systemctl daemon-reload
if systemctl is-active --quiet keysink; then
  # 重部署：换新二进制/新 unit 必须重启，只 enable --now 不会动在跑的旧实例
  systemctl restart keysink
else
  systemctl enable --now keysink
fi

cat <<EOF

安装完成。

下一步（添加路由，人类用户 $HUMAN）：
  sudo -u keysink keysink route add claude --base-url https://api.anthropic.com
  # 终端里依次引导：名称 / base URL / 上游协议 / key 值（隐藏回显，只进不出）
  # 脚本里：printf %s "\$KEY" | sudo -u keysink keysink route add <name> --base-url ...

agent 侧配置（route add 末尾会打印这两行）：
  BASE_URL=http://127.0.0.1:8787
  TOKEN=ks_...

vault 文件：$VAULT_HOME
服务状态：systemctl status keysink
EOF
