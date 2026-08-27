# svcsite

[English](README.md) | 简体中文

面向 Agent 的 Android ARM64 syscall 追踪与调用点分析 CLI。

svcsite 通过 ADB 和 KernelPatch Module（KPM）采集 Android 进程的有界
syscall 证据，并将运行时地址解析为模块与偏移，供 IDA、Ghidra 等静态分析
工具使用。

## 核心能力

- 按包名或精确 PID 限定目标。
- 记录 syscall 参数、PC、LR 和最多 16 层 ARM64 返回地址。
- 返回有界事件、调用点排行、计数和证据质量。
- 提供确定性 JSON、稳定错误码和绝对产物路径。

## 环境要求

- macOS、Python 3.11+ 和 ADB
- 具备 root、KernelPatch 和 `kpatch` 的 Android ARM64 设备
- KernelPatch SuperKey
- 构建 KPM 时使用 Android NDK r29+

当前验证基线为 Pixel 6、Android 14 和 arm64-v8a。

## 安装

```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Agent 调用说明见 [`SKILL.md`](SKILL.md)。使用前确保 `svcsite` 位于 `PATH`。

## SuperKey

将 SuperKey 保存到权限为 `0600` 的文件：

```bash
mkdir -p ~/.config/svcsite
install -m 600 /dev/null ~/.config/svcsite/superkey
${EDITOR:-vi} ~/.config/svcsite/superkey
```

CLI 也支持 `SVCSITE_SUPERKEY_FILE` 和 `SVCSITE_SUPERKEY`，不会将密钥写入
命令输出、日志或采集产物。

## Agent 工作流

Agent 调用统一传入 `--json`。stdout 只输出一个 JSON 对象，诊断信息写入
stderr；失败时返回稳定错误码和非零退出码。

检查环境和模块状态：

```bash
svcsite doctor --device SERIAL --json
svcsite status --device SERIAL --json
```

执行一次有界采集：

```bash
svcsite capture \
  --device SERIAL \
  --package io.example.target \
  --target-mode launch \
  --duration 15 \
  --output ./captures \
  --kpm ./kpm/svcsite.kpm \
  --json
```

`--package` 和 `--pid` 必须指定一个。包名目标支持 `attach`、`launch` 和
`restart`；PID 目标使用精确 TGID 过滤和 `attach` 模式。

首次加载或更新时传入 `--kpm`。svcsite 比较 SHA-256，设备模块一致时跳过
安装。

离线查询已保存的 session：

```bash
svcsite query /absolute/path/to/captures/SESSION_ID \
  --syscall openat,read \
  --contains /proc/ \
  --limit 20 \
  --json
```

`query` 一次返回 `events`、调用点排行 `callsites`、`counts` 和 `quality`。
`--limit` 同时限制两个列表。可使用 `--pid`、`--tid`、`--contains` 或
`--module-id` 聚焦证据。

正常完成的 capture 会关闭监控并排空事件缓冲区。中断后可安全重试清理命令：

```bash
svcsite stop --device SERIAL --json
```

## Session 与地址

每个 session 包含 `manifest.json`、`events.bin` 和 `maps/` 下的进程映射
快照。映射获取失败会记录 warning，已采集的 syscall 记录仍可查询。

原始 LR 和 backtrace 值是 ARM64 返回地址。派生 callsite 会减去 4 字节，
并以模块偏移表示调用指令。标识具体二进制时使用 `module_id` 或完整映射路径；
`module` 用于展示。

## 开发

```bash
make check
make kpm
```

## 安全与许可证

svcsite 仅用于经过授权的安全研究和逆向分析。加载 KPM 会改变设备内核运行状态，
并可能导致设备崩溃或重启。

KPM 来源和修改边界见 [`UPSTREAM.md`](UPSTREAM.md)。svcsite 采用
[GNU General Public License v2.0 only](LICENSE)。
