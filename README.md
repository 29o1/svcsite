# Z9Null Monitor CLI

面向 Codex、Claude Code 等 AI Agent 的 Android syscall 动态分析 CLI。

CLI 通过 ADB、root shell 和 KernelPatch Module（KPM）采集目标进程的
syscall 运行时证据，并以稳定、可查询的 JSON/JSONL 与二进制产物提供给
Agent。

## 项目定位

Z9Null Monitor 是独立的 syscall 观测工具，Agent 根据分析目标自行决定何时调用本工具。

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

## 当前能力

- `doctor`：检查 ADB、设备、ABI、root、kpatch 和 SuperKey 配置。
- `status`：读取 `z9null_monitor` KPM 状态。
- `stop`：幂等地暂停 KPM 监控。
- `capture`：按包名/UID 完成一次有界采集并生成独立 session。
- `query`：对 session 做有界过滤、调用点聚合或 JSONL 导出。
- `address resolve`：把运行时地址归一化为模块、基址和模块内偏移。
- `bench run`：收敛模块后对受控负载执行多次采集并生成基准报告。
- `bench compare`：对比两份基准报告，输出带噪声判定的指标表。
- 采集目标 UID 下所有进程的 `/proc/<pid>/maps`，并自动补充事件地址信息。
- KPM 记录独立的 PC、LR 和最多 16 层 FP-chain；查询额外给出 ARM64
  返回地址对应的调用指令位置（`return_address - 4`）。
- 二进制 v1/v2 事件解析、损坏重同步、截断检测和序列缺口统计。
- 使用流式事件扫描和 maps 区间索引处理大型 session，避免把全部事件对象
  常驻内存。
- 本地二开 KPM 源码及可复现构建入口。

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

默认要求 `z9null_monitor` 已加载；模块缺失时返回稳定错误
`MODULE_NOT_LOADED`。部署模块有两种方式：

- `--load-module PATH`：无条件卸载并加载指定模块（修复通道）。
- `--kpm PATH`：收敛语义。CLI 对比本地文件 sha256 与设备上的部署指纹，
  一致则跳过装卸（约一次 status 往返），不一致才替换。重建 KPM 后下一次
  采集自动使用新模块，未重建时零额外开销。

```bash
z9mon capture \
  --device SERIAL \
  --package io.example.target \
  --duration 15 \
  --target-mode launch \
  --output ./captures \
  --kpm ./kpm/z9null_monitor.kpm \
  --json
```

`--kpm` 的路径也可以写进配置文件，之后所有 `capture` 和 `bench run` 自动
生效（命令行参数优先）：

```bash
mkdir -p ~/.config/z9mon
printf '{"kpm_path": "/absolute/path/to/z9null_monitor.kpm"}' \
  > ~/.config/z9mon/config.json
```

首次模块加载会安装内核 hook；CLI 为该步骤保留至少 60 秒的单命令等待时间，
其余设备命令仍使用 `--timeout`（默认 15 秒）。

后续采集可省略 `--load-module`：

```bash
z9mon capture \
  --device SERIAL \
  --package io.example.target \
  --duration 15 \
  --target-mode restart \
  --output ./captures \
  --json
```

`--target-mode attach`（默认）不修改 App 生命周期；`launch` 启动目标但不先
清理状态；`restart` 会先 `force-stop` 再启动，不会清除 App 数据。KPM 按目标
UID 采集，因此同 UID 的进程都会进入原始 session，随后可按 PID/TID 查询。

从 v0.7.0 起，生命周期参数统一为 `--target-mode`，查询形态统一为
`--mode events|stats|callsites`；默认 syscall 集合不再需要显式 preset。旧参数
`--launch`、`--restart`、`--stats`、`--callsite-stats` 和 `--preset` 已移除，避免
Agent 组合出互相冲突的状态。

不提供 `--syscall` 时使用 `reverse-basic` 集合。自定义 syscall 可重复或使用
逗号分隔：

```bash
z9mon capture \
  --package io.example.target \
  --duration 10 \
  --syscall openat,read,ptrace \
  --json
```

自定义项限定为 KPM 中已声明正确参数个数的 Tier1/Tier2 syscall；例如
`openat`、`write`、`sendmsg`、`execveat`。不对任意 syscall 动态猜测参数
个数，未支持项返回 `SYSCALL_UNSUPPORTED`。

每次采集生成：

```text
captures/SESSION_ID/
├── manifest.json
├── events.bin
├── summary.json
└── maps/
    ├── post-launch-PID.maps
    ├── pre-stop-PID.maps
    └── recovery-PID.maps
```

`maps/` 保留启动后和停止前的进程映射原始快照；若事件中出现尚未覆盖的
PID，还会尝试生成 recovery 快照。地址解析直接读取这些快照；旧版本 session
携带的 `modules.json` 仍然可用。maps 获取失败只记录 warning，不会让一次
已完成的 syscall 采集失败。

查询不会修改设备状态：

```bash
z9mon query ./captures/SESSION_ID --mode stats --json
z9mon query ./captures/SESSION_ID \
  --syscall openat,read \
  --contains /proc/ \
  --limit 50 \
  --json
z9mon query ./captures/SESSION_ID \
  --syscall connect \
  --limit 100 \
  --format jsonl

z9mon query ./captures/SESSION_ID \
  --mode callsites \
  --limit 20 \
  --json

z9mon query ./captures/SESSION_ID \
  --module-id 'file:DEVICE:INODE:/absolute/device/path/libtarget.so' \
  --mode callsites \
  --limit 20 \
  --json

z9mon address resolve ./captures/SESSION_ID \
  --pid 12345 \
  --address 0x7a12345678 \
  --json
```

普通查询默认最多返回 20 条 compact 事件；需要完整映射字段时使用
`--detail full`。当 session 含有映射数据时，`query` 会保留原始
`pc`、`caller`、`clone_fn` 和 backtrace 地址，并增加调用点对应的 resolved
字段。解析结果只做
运行时地址归一化（`module`、`module_id`、`module_base`、`module_offset`）。
`module` 是适合展示的 basename；`module_id` 组合完整规范化路径、设备号和
inode，用于区分不同 App 中同名的 `base.apk` 或 `.so`。缺少该字段时会在查询
阶段自动推导。v0.7.0 不拉取 ELF，也不提供符号名或源码行信息；没有映射数据
的 session 仍可查询。

`--module-id` 使用唯一模块标识筛选包含该模块调用点的事件。`--mode stats`
返回 syscall、PID 和有界模块排名，便于 Agent 发现目标 `module_id`；
`--mode callsites` 按 syscall、模块和模块内偏移聚合唯一调用点，适合交给静态
分析工具继续处理。

`caller` 和 FP-chain 中的地址是 ARM64 返回地址。查询保留这些原始证据，
并额外输出 `caller_callsite`、`backtrace_callsites` 及对应的 resolved 字段，
方便直接把调用指令的模块内偏移交给静态分析工具。旧 KPM 的 backtrace 会
重复包含 PC；该位置的 callsite 返回 `null`，避免错误执行 `PC - 4`。

`--json` 模式下 stdout 只包含一个紧凑 JSON 对象。诊断信息写入 stderr，
并使用稳定的错误代码和进程退出码。capture warning 位于结果信封顶层并使用
结构化 `code`、`phase`、PID 等字段；重复的短生命周期 PID maps warning 会
聚合，完整明细仍保存在 `manifest.json`。
`--format jsonl` 仅用于导出 events，不能与 `--json` 或聚合查询模式组合。

## 构建 KPM

先设置 Android SDK/NDK，再执行：

```bash
make kpm
```

默认使用仓库中的 `KernelPatch` submodule，也可显式覆盖：

```bash
make kpm KP_DIR=/absolute/path/to/KernelPatch
```

KPM v1.4.0 只保留 CLI 实际使用的控制命令和 binary v2 writer。CLI v0.8.0 仍可
读取设备上已加载的旧 KPM 状态并执行兼容采集；模块替换发生在显式传入
`--load-module`（无条件）或 `--kpm`（指纹不一致时）的时候。

## 基准测试（bench）

衡量每次代码改动对采集质量和查询性能的实际影响：

```bash
make kpm && make bench            # 或 z9mon bench run --kpm ... --json
z9mon bench compare \
  bench/OLD_RUN/report.json \
  bench/NEW_RUN/report.json \
  --json
```

`bench run` 会先把设备上的模块收敛到 `--kpm` 指定的构建（跳过条件同上），
然后对受控负载（默认 `io.z9null.tracefixture`，仓库内 `local-test-app`
提供确定性 syscall 循环）执行默认 5 × 15 秒的 restart 采集。每个 trial
校验采集契约（监控关闭、缓冲清零），计算证据质量指标（调用点解析率、
回溯深度、唯一调用点数、信噪比）和完整性指标（丢弃/缺口/解析错误），
并在事件数中位数的 session 上对三种查询模式计时（含每万事件归一化）。
默认只保留中位数 session，其余删除；报告写入 `bench/<run_id>/report.json`
与 `report.md`，带 git 提交、模块版本和 sha256 指纹。

`bench compare` 对比两份报告：性能指标置顶，只有变化超出 trial 间四分位
距构成的噪声带才判定 `improved`/`regressed`，否则标 `flat`；包名或时长
不一致时给出不可比警告。人类可读表格写入 stderr，结构化结果仍以单个
JSON 对象输出到 stdout。报告不包含 SuperKey。

## 验证

```bash
make check
```

`make check` 对提交内的 Python 源码执行语法检查。设备端验收命令为：

```bash
z9mon capture \
  --package TARGET \
  --duration 15 \
  --target-mode launch \
  --output ./captures \
  --json
```

## 来源

KPM 基于 `XiaoWaaay/SVCMonitors` 的本地二次开发版本迁移而来，Python CLI
为本仓库新增实现。详细来源、基准提交和修改边界见
[UPSTREAM.md](UPSTREAM.md)。
