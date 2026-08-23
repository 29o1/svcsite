# svcsite

Android ARM64 syscall tracing and callsite analysis CLI for agents.

svcsite 通过 ADB、root shell 和 KernelPatch Module（KPM）采集目标进程的
syscall 运行时证据，并将地址解析到具体模块及偏移。它负责提供可复查的动态
证据，不负责符号恢复或反编译。

## 核心能力

- 按包名或精确 PID 进行有界 syscall 采集。
- 记录 PC、LR 和最多 16 层 ARM64 FP-chain 回溯。
- 结合进程 maps，将调用点解析为 `module_id` 和 `module_offset`。
- 以稳定 JSON、错误码和绝对产物路径向 Agent 提供证据。

## 环境

- Python 3.11+
- ADB
- Android ARM64 设备
- root、KernelPatch、`kpatch` 和 SuperKey
- 构建 KPM 时需要 Android NDK r29+

当前验证基线为 macOS 主机、Pixel 6、Android 14 和 arm64-v8a。

## 安装

```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Agent 可使用仓库根目录的 `SKILL.md` 了解调用约定；运行时应确保 `svcsite`
位于 `PATH`。

## SuperKey

默认从权限为 `0600` 的文件读取：

```bash
mkdir -p ~/.config/svcsite
install -m 600 /dev/null ~/.config/svcsite/superkey
${EDITOR:-vi} ~/.config/svcsite/superkey
```

也可以使用 `SVCSITE_SUPERKEY_FILE` 指定文件，或使用
`SVCSITE_SUPERKEY` 环境变量。CLI 不输出 SuperKey。

## 使用

Agent 调用一律使用 `--json`。JSON 模式下 stdout 只包含一个 JSON 对象，
诊断信息写入 stderr。

### 1. 检查环境

```bash
svcsite doctor --device SERIAL --json
svcsite status --device SERIAL --json
```

### 2. 采集

```bash
svcsite capture --device SERIAL --package io.example.target --duration 15 \
  --target-mode launch --output ./captures --kpm ./kpm/svcsite.kpm --json
```

`--package` 和 `--pid` 二选一。包名目标支持 `attach`、`launch` 和
`restart`；PID 目标为精确 TGID 过滤，只支持 `attach`。

首次加载或模块版本不匹配时显式传入 `--kpm`。CLI 根据本地文件 sha256
收敛设备模块；匹配时跳过替换。模块已经匹配后可省略该参数。

默认采集面向逆向分析的基础 syscall 集合。使用 `--syscall` 可进一步限定：

```bash
svcsite capture --device SERIAL --pid 1687 --duration 10 \
  --syscall openat,read,connect,sendto --json
```

每次采集生成独立 session：

```text
captures/SESSION_ID/
├── manifest.json
├── events.bin
└── maps/
    └── SNAPSHOT-PID.maps
```

`manifest.json` 包含采集参数、摘要和 warning；`events.bin` 保存 syscall
证据；`maps/` 用于地址解析。maps 获取失败只产生 warning，不会使已经完成的
syscall 采集失效。

### 3. 查询

```bash
svcsite query ./captures/SESSION_ID --syscall openat,read \
  --contains /proc/ --limit 20 --json
```

query 是纯离线读操作，返回：

- `events`：具体 syscall、进程、线程、参数和回溯。
- `callsites`：按频次排列的 syscall × module × module_offset。
- `counts`：匹配数、返回数和截断数。
- `quality`：内核丢弃、序列缺口和解析器状态。

`--limit` 同时限制 events 和 callsites。可使用 `--pid`、`--tid`、
`--contains` 或 `--module-id` 缩小结果。

`module` 只是展示名；跨映射比较时应使用 `module_id` 或完整 `path`。
原始 caller 和 backtrace 值是 ARM64 返回地址，派生 callsite 已减 4，可直接
将其 `module_offset` 交给 IDA 等静态分析工具。

## 构建与验证

```bash
make check
make kpm
```

`make check` 运行 Python 语法检查和单元测试。`make kpm` 使用固定的
KernelPatch submodule 构建 `kpm/svcsite.kpm`。

## 使用边界

本项目仅用于获得授权的安全研究与逆向分析。加载 KPM 会修改设备内核运行状态，
可能导致目标设备崩溃或重启；请在测试设备上使用并提前备份重要数据。

## 来源与许可证

KPM 基于 `XiaoWaaay/SVCMonitors` 的本地二次开发版本迁移而来。上游固定
提交、作者和修改边界见 [UPSTREAM.md](UPSTREAM.md)。

svcsite 采用 [GNU General Public License v2.0 only](LICENSE)。
