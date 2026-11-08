# Linux 系统服务

[← 中文 README](../../README.zh-CN.md)

```bash
sudo keysink deploy
```

一条命令完成：创建 `keysink` 系统用户和 0700 的保险库目录，把二进制安装到
`/usr/local/bin/keysink`，写入 systemd unit 和 sudoers 规则（针对执行 sudo 的
管理员），交互式初始化保险库（隐藏密码，输入两次），然后启用服务。幂等：重跑
即原地升级并重启。移除是对称的：`sudo keysink uninstall`。

这不仅是便利：正是专用 uid 让保险库文件对以你身份运行的 agent 不可及（见
[security.md](security.md#the-other-channels-same-user-not-same-process)）。

unit 在保险库存在之前拒绝启动（`ConditionPathExists`）。如果部署主机上没有
终端，手动交互式初始化：

```bash
sudo -u keysink /usr/local/bin/keysink --home /var/lib/keysink init
```

或完全无头（没有 TTY 时 `init` 拒绝提示输入，所以用管道传密码）：

```bash
printf '%s\n' "$MASTER_PASSWORD" | sudo -u keysink /usr/local/bin/keysink \
  --home /var/lib/keysink init --password-stdin
```

之后管理命令经 `sudo -u keysink /usr/local/bin/keysink …` 执行；每次调用都重新
认证（`timestamp_timeout=0`），所以 agent 无法静默运行它们。

`deploy` 仅支持 Linux + systemd；个人使用直接运行 `keysink serve` 即可。
`KEYSINK_MASTER_KEY` / `KEYSINK_MASTER_KEY_FILE` 让 identity 存放在保险库目录
之外，这正是 systemd 的 `LoadCredential` 想要的。
