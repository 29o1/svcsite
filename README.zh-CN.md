# svcsite

[English](README.md) | 简体中文

在命令行中追踪 Android ARM64 syscall 并分析调用点。

svcsite 通过 ADB 和 KernelPatch Module（KPM）记录 syscall 参数、PC、LR
和最多 16 层返回地址，解析为映射模块及偏移。
JSON 输出便于脚本和 AI Agent 集成。

## 环境要求

- macOS、Python 3.11+ 和 ADB
- 具备 root、KernelPatch、`kpatch` 和 SuperKey 的 Android ARM64 设备
- `make` 和 Android NDK（构建已在 r29 上验证）

当前验证基线为 Pixel 6、Android 14 和 arm64-v8a。

## 安装与构建

将下面的 `NDK_DIR` 替换为已安装的 NDK 目录：

```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
make kpm NDK_DIR="/absolute/path/to/android-ndk-r29"
```

构建产物为 `kpm/svcsite.kpm`。运行 `svcsite` 时保持虚拟环境处于激活状态。

## SuperKey

将 SuperKey 作为单行文本保存到权限为 `0600` 的文件。以下准备命令保留已有内容：

```bash
mkdir -p ~/.config/svcsite
(umask 077 && touch ~/.config/svcsite/superkey)
chmod 600 ~/.config/svcsite/superkey
${EDITOR:-vi} ~/.config/svcsite/superkey
```

可用 `--key-file` 指定其他文件。密钥不会写入命令输出、日志或采集产物。

## 快速开始

在仓库根目录执行。将 `SERIAL` 替换为 `adb devices` 显示的序列号，
将 `io.example.target` 替换为应用包名。检查环境后采集 15 秒，期间操作目标应用：

```bash
svcsite doctor --device SERIAL --json
svcsite capture --device SERIAL --package io.example.target \
  --target-mode launch --duration 15 --output ./captures \
  --kpm "$PWD/kpm/svcsite.kpm" --json
```

首次加载或更新时传入 `--kpm`。svcsite 比较 SHA-256，设备模块一致时跳过
安装。

从采集结果的 `data.session` 复制路径，离线查询：

```bash
SESSION='/absolute/path/to/captures/SESSION_ID'
svcsite query "$SESSION" --limit 20 --json
```

查询结果的 `data` 包含 `events`、调用点排行 `callsites`、`counts` 和
`quality`。`--limit` 默认 20，同时限制两个列表；可通过 `--syscall`、
`--contains`、`--pid`、`--tid` 和 `--module-id` 过滤。

采集结束自动关闭监控并排空缓冲区。检查状态或在中断后清理：

```bash
svcsite status --device SERIAL --json
svcsite stop --device SERIAL --json
```

`--package`（按 UID 过滤，可能包含多个进程）与 `--pid`（精确单进程，
仅支持 attach）必须二选一。`--target-mode` 支持 `attach`（默认）、
`launch` 和 `restart`（强制停止后启动）。

默认采集 `reverse-basic` 的 16 个 syscall，可用 `--syscall openat,read`
改选 KPM 支持的 syscall。

## 输出与参考

Session 包含 `manifest.json`、`events.bin` 和 `maps/` 快照。映射获取失败
不影响 syscall 记录，但可能无法确定模块归属。通过 `quality` 检查事件丢失；
`--limit` 导致的列表截断仅影响展示。

`--json` 输出单个紧凑 JSON 对象，失败时提供稳定的 `error.code` 和非零退出码。
完整参数见 `svcsite capture --help` 和 `svcsite query --help`；
Agent 集成与证据解释见 [`SKILL.md`](SKILL.md)。开发检查使用 `make check`。
