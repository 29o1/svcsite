# Z9Null Monitor CLI

面向 Codex、Claude Code 等 AI Agent 的 Android syscall 动态分析 CLI。

CLI 通过 ADB、root shell 和 KernelPatch Module（KPM）采集目标进程的
syscall 运行时证据，并以稳定、可查询的 JSON/JSONL 与二进制产物提供给
Agent。

## 项目定位

Z9Null Monitor 是独立的 syscall 观测工具，不负责包装或编排 IDA、
GumTrace、Frida、Reqable，也不在 CLI 内嵌大模型。Agent 根据分析目标自行
决定何时调用本工具。

```text
Codex / Claude Code / Human
              │
           z9mon CLI
              │ ADB + root + kpatch ctl0
              ▼
    Android ARM64 KernelPatch KPM
              │
              ▼
       binary event artifacts
```

## 当前状态

第一阶段已经建立：

- `doctor`：检查 ADB、设备、ABI、root、kpatch 和 SuperKey 配置。
- `status`：读取 `z9null_monitor` KPM 状态。
- `stop`：幂等地暂停 KPM 监控。
- 本地二开 KPM 源码及可复现构建入口。

`capture`、二进制协议解析和 `query` 将在下一阶段实现。

## 安装

要求 Python 3.11 或更高版本：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

克隆仓库时需要初始化固定版本的 KernelPatch：

```bash
git submodule update --init --recursive
```

## SuperKey

默认从权限为 `0600` 的文件读取：

```bash
mkdir -p ~/.config/z9mon
install -m 600 /dev/null ~/.config/z9mon/superkey
${EDITOR:-vi} ~/.config/z9mon/superkey
```

也可以使用 `Z9MON_SUPERKEY_FILE` 指定其他文件，或以
`Z9MON_SUPERKEY` 作为备用来源。CLI 不输出 SuperKey。

## 使用

```bash
z9mon doctor --device SERIAL --json
z9mon status --device SERIAL --json
z9mon stop --device SERIAL --json
```

`--json` 模式下 stdout 只包含一个紧凑 JSON 对象。诊断信息写入 stderr，
并使用稳定的错误代码和进程退出码。

## 构建 KPM

先设置 Android SDK/NDK，再执行：

```bash
make kpm
```

默认使用仓库中的 `KernelPatch` submodule，也可显式覆盖：

```bash
make kpm KP_DIR=/absolute/path/to/KernelPatch
```

## 验证

```bash
make check
```

## 来源

KPM 基于 `XiaoWaaay/SVCMonitors` 的本地二次开发版本迁移而来，Python CLI
为本仓库新增实现。详细来源、基准提交和修改边界见
[UPSTREAM.md](UPSTREAM.md)。
