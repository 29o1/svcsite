---
name: svcsite
description: Capture and query Android ARM64 syscall evidence on rooted KernelPatch devices for anti-debugging, network-request, and device-registration analysis, with process attribution and module-offset callsites.
---

# svcsite — Android syscall 动态证据

对目标 app 或精确 PID 采集 syscall 事件，将 PC、返回地址和 FP 回溯解析到
映射模块（APK、共享库或可执行文件）及偏移。证据到模块偏移为止，不提供符号名。

验证基线：Pixel 6 / Android 14 / arm64-v8a + root + KernelPatch + SuperKey。

```bash
svcsite <command> --json
PYTHONPATH=/absolute/path/to/svcsite/src python3 -m svcsite <command> --json
```

如果无法定位命令或仓库，报告工具不可用。不要读取 SuperKey 内容，也不要退回到
裸 `kpatch kpm ctl0`。

## 采集能力选择

先按分析目标选择采集范围，再执行下方工作流。**默认 16 个是通用起点；三组配方
是通过 `--syscall` 指定的场景集合，显式选择会替换默认集合，不会自动叠加。**
它们不是三个独立采集器，也没有 `--profile` 参数。可按已有线索组合或缩小列表，
但只能选择 KPM 静态白名单内的 syscall；保留 `close` 才能启用跨事件 fd 关联。

| 选择 | 适用目标 | 主要证据 |
|---|---|---|
| 默认 16 个 | 初步了解应用行为，尚无明确方向 | 文件访问、调试限制、网络连接、进程与内存活动 |
| 反调试分析 | 定位环境检查、调试限制及检测后的响应 | `/proc` 等路径访问、调试限制、信号处理与发送、主动退出的参数及调用点 |
| 网络请求分析 | 追踪连接、收发、失败原因及发起模块 | socket 对端、返回长度、有限数据预览、`SO_ERROR` |
| 设备注册分析 | 观察注册流程中的本地状态与网络活动 | 文件/数据库读写、重命名、`ioctl` 参数、连接与收发 |

以下命令替换 `SERIAL` 和包名；单进程场景改用 `--pid PID --target-mode attach`。
首次加载或更新模块时，显式添加 `--kpm /absolute/path/to/svcsite.kpm`。
`attach` 适合操作正在运行的应用，`launch` 启动应用，`restart` 会强制停止后启动；
根据目标操作选择，注册场景需先让应用处于待注册状态，采集命令不会清除应用数据。

### 默认：通用观察（16 个）

不传 `--syscall`，自动使用 `reverse-basic`：
`openat,close,read,readlinkat,newfstatat,ptrace,prctl,socket,connect,sendto,recvfrom,munmap,clone,execve,mmap,mprotect`。
此集合没有覆盖全部读写方式；已有明确目标时使用相应配方。

```bash
svcsite capture --device SERIAL --package com.example.app --target-mode launch \
  --duration 15 --output ./captures --json
```

### 反调试：文件检查、调试限制与信号退出（17 个）

```bash
svcsite capture --device SERIAL --package com.example.app --target-mode restart \
  --syscall openat,close,read,pread64,readlinkat,getdents64,faccessat,newfstatat,ptrace,prctl,seccomp \
  --syscall kill,tgkill,exit,exit_group,rt_sigaction,rt_sigprocmask \
  --duration 10 --output ./captures --json
```

先查询 `/proc/` 路径和调试相关调用，再定位目标模块中的调用点。读取 maps 或
status 本身不证明存在反调试；结合内容、返回值和调用上下文判断。
`kill/tgkill` 观察信号发送，`exit/exit_group` 观察主动退出，
`rt_sigaction/rt_sigprocmask` 观察信号处理器与屏蔽配置。这六项目前仅记录入口，
不能据此确认信号发送或配置成功；结合目标 PID/TID、信号编号、前序检测和调用点
判断是否属于反调试响应。已有线程或内存线索时再补相应 syscall。

### 网络请求：连接与收发（13 个）

```bash
svcsite capture --device SERIAL --package com.example.app --target-mode attach \
  --syscall socket,connect,close,read,write,readv,writev,sendto,recvfrom,sendmsg,recvmsg,getsockopt,shutdown \
  --duration 10 --output ./captures --json
```

先查看 `connect`、`getsockopt` 与 fd 对端关联，再查收发及调用点。
`-EINPROGRESS` 表示连接待完成，需结合后续证据判断。syscall 层通常不能获得
TLS 明文，数据预览也不是完整 HTTP 请求；系统 DNS 服务的对外流量可能在目标
UID 之外。

### 设备注册：本地状态与网络活动（25 个）

```bash
svcsite capture --device SERIAL --package com.example.app --target-mode restart \
  --syscall openat,close,read,write,pread64,pwrite64,renameat,renameat2,unlinkat,mmap,ioctl,socket,connect,sendto,recvfrom,sendmsg,recvmsg,getsockopt \
  --syscall readv,writev,fstat,newfstatat,faccessat,fcntl,readlinkat \
  --duration 15 --output ./captures --json
```

在采集窗口内触发注册，结合文件路径、读写、网络活动和调用点分析。
`readv/writev` 补齐向量读写；`fstat/newfstatat/faccessat` 观察已有状态检查，
`fcntl` 观察锁和 fd 配置，`readlinkat` 观察路径解析。状态查询目前未采集返回值，
不能据入口断言文件存在或可访问。`ioctl` 提供参数、返回结果及已观察的 fd 路径，
不解码 Binder 业务或设备 ID；已映射或缓存的系统属性读取也可能不产生新 syscall。
`mmap` 返回地址可与文件 fd 关联，但映射后的内存访问不会逐条记录。
`renameat/renameat2/unlinkat` 的真实返回值用于区分尝试和成功。

区分首次注册、已有状态启动和重复注册；`restart` 不清除注册状态，重装也可能恢复
备份数据。当前未覆盖 `fsync/fdatasync/ftruncate/msync`，不能仅凭写入成功断言可靠
落盘。HTTPS 内容、其他 UID 的服务内部行为需结合对应工具和上下文分析。

已有 session 时直接查询；`query --syscall` 只过滤已记录的事件，不能补采未选中的
调用。三组配方均在采集后使用有界 `query` 并检查 `quality`，详见下方工作流。

## 硬性约束

- Agent 调用一律使用 `--json`；stdout 必须恰好一个 JSON 对象。
- `capture` 是设备写操作，`query` 是纯离线读操作。
- 不打印、记录或写入 SuperKey。
- 模块加载必须显式使用已知绝对路径的 `--kpm`。
- 不直接读取或自行解析 `events.bin`，使用有界 `query`。
- 成功的 capture 保证 monitoring disabled 且 `events_buffered == 0`。

## 工作流

```text
doctor/status（按需） → capture → query
```

### 1. 预检

```bash
svcsite doctor --device SERIAL --json
svcsite status --device SERIAL --json
```

`status` 和 `stop` 可安全重试。上一次采集中断、仍在监控或缓冲区非空时，
调用 `stop` 后重新检查状态。正常空闲状态是 `enabled == false` 且
`events_buffered == 0`。

### 2. 采集

执行上方选定的采集命令，在采集窗口内触发待分析行为。

- `--package PKG` 和 `--pid PID` 二选一。
- package 按 UID 过滤，可能采集同 UID 的多个进程；可使用 `attach`、`launch`
  或 `restart`。
- PID 是精确 TGID 过滤，只支持 `attach`。
- 从成功结果的 `data.session` 读取绝对路径，后续记为 `SESSION`。
- session 包含 `manifest.json`、`events.bin` 和 `maps/`；摘要位于 manifest。

如果 capture 返回 `MODULE_NOT_LOADED` 或 `MODULE_VERSION_UNSUPPORTED`，且能确定
当前仓库 KPM 的绝对路径，则给同一条 capture 添加
`--kpm /absolute/path/to/svcsite.kpm` 并重试一次。该参数按 sha256 收敛，
已一致时不会替换。模块加载与 hook 安装的单次命令至少等待 60 秒；不要用短超时
误判失败，也不要猜测 KPM 路径或反复重试。

maps 在启动后、停止前抓取；package 采集中约每 0.5 秒另行发现新 PID 并抓取 maps，
成功保存过的 PID 不在轮询中重复读取。轮询和 ADB 有延迟，仍可能错过短命进程，
也不能完整记录中途 dlopen、卸载或 PID 复用；不根据父进程 maps 猜测子进程归属。
maps 获取失败只产生 warning：syscall 行为证据仍有效，但模块归属可能不完整，
不得据此断言具体调用模块。判断影响时同时看未取得 maps 的进程数和事件占比。

数据量较大时先检查 manifest 的 `summary.by_syscall`，按问题缩小 `--syscall`
或采集窗口。精确 PID 会排除其他进程，只在分析范围明确时使用；查询过滤不会减少
已采集文件大小。不要默认采样、删掉 read/pread64 或合并入口/返回来压缩证据。

采集创建 session 后失败时，错误详情提供 `session` 和 `manifest` 的绝对路径。
工具会尽力保存已取得的事件与 maps；manifest 的 `status` 为 `failed`，
`failures` 按发生顺序记录错误代码及阶段。`module.final_status` 为 `null`
表示最终状态未知，不能据此断言监控已停止。若失败阶段含 `manifest-write`，
manifest 可能未能写入，应以错误详情为准。

设备型号等可选元数据读取失败只产生 warning。采集等待期间中断后，若停止、
排空和保存均成功，仍返回成功及 `CAPTURE_INTERRUPTED` warning，manifest 的
`status` 为 `interrupted`。

### 3. 查询

先查看会话概况，再按所选场景收窄。例如反调试分析可过滤 `/proc/`：

```bash
svcsite query "$SESSION" --limit 20 --json
svcsite query "$SESSION" --syscall openat,read,pread64 --contains /proc/ \
  --limit 20 --json
```

一次 query 返回：

- `events`：具体 syscall、进程、线程、参数和回溯。
- `callsites`：按频次排列的 syscall × module × module_offset。
- `counts`：匹配数、返回数和截断数。
- `quality`：内核丢弃、序列缺口和解析器状态。

`--limit` 默认 20，同时限制 events 和 callsites。使用 `--pid`、`--tid`、
`--contains` 或 `--module-id` 缩小结果。`module_id` 从首次查询的 resolved
字段或 callsites 中取得，再按精确值过滤：

```bash
svcsite query "$SESSION" --module-id "$MODULE_ID" --limit 20 --json
```

## 证据解释

```text
events[].process                         进程、线程、UID 和 comm
events[].description                     syscall 参数，如路径和 flags
events[].registers.pc_resolved           syscall 指令位置，通常位于系统库
events[].registers.caller_callsite_resolved
                                          syscall wrapper 的直接调用位置
events[].backtrace_callsites_resolved[]  从近到远的 FP-chain 调用位置
callsites[]                               聚合后的高频调用位置
```

从靠近 syscall 的帧开始，选择第一个已解析的目标模块或非系统模块；不要默认选择
回溯最外层。无法解析时不要推断模块归属。

`module` 只是展示名；不同 APK 或库可能同名，比较映射时使用 `module_id` 或完整
`path`。原始 caller 和 backtrace 值是 ARM64 返回地址；派生 callsite 已减 4。
不要把 syscall PC 当作返回地址。

## 证据质量

```text
quality.kernel_dropped                   0 为无已报告内核丢弃；null 为未知；大于 0 为丢弃
quality.sequence.gaps                    应为 0
quality.parser.invalid_records           应为 0
quality.parser.skipped_bytes             应为 0
quality.parser.truncated_bytes           应为 0
```

任一已知质量指标异常时，在结论中明确限制，不要把缺失视为未发生。指标全为零
也只说明所选范围和采集窗口内未发现这些损失，不能证明所有目标行为均被覆盖。

## 错误处置

| code | 动作 |
|---|---|
| `MODULE_NOT_LOADED` / `MODULE_VERSION_UNSUPPORTED` | 使用已知绝对 `--kpm` 路径重试 capture 一次 |
| `SYSCALL_UNSUPPORTED` | 去掉该 syscall，不枚举试探 |
| `MAPS_UNAVAILABLE` | 保留 syscall 结论，不做缺乏证据的模块归属 |
| `KPM_STATUS_INVALID` / `KPM_MONITORING_ENABLED` / `KPM_DRAIN_TIMEOUT` | capture 未正常完成；检查错误详情和 manifest 的最终状态，再按需 stop/status |
| `MODULES_NOT_FOUND` | 报告 session 缺少映射，不能使用 module 过滤 |
| `SUPERKEY_*` / `DEVICE_*` | 原样报告给用户 |
| `USAGE_ERROR` | 按 CLI 参数修正一次 |

## 返回结果与 fd 证据

新采集要求 KPM 1.8.0 或更新版本。旧 binary v1/v2 文件仍可离线查询；新文件
继续使用 binary v2 的固定布局和 16 层 FP 回溯。

- `events[].phase` 为 `entry`、`exit` 或旧记录的 `unknown`。
- `registers.ret_valid` 为 true 才能将 `registers.ret` 当作真实返回值。
  未采集返回值时 `ret` 为 null；`ret_hex` 始终保留原始存储位，包括旧占位 0。
- `exit` 的 `entry_seq` 关联同一进程、线程和 syscall 的入口记录。入口不证明
  调用成功；缺失配对时不得拼接其他调用。旧 read 和带 `new_tid=` 的 clone 返回
  记录仍能识别。新 clone 保持独立的返回记录，不提供 `entry_seq`。
- `openat`、`close`、`read/write`、`pread64/pwrite64`、`readv/writev`、
  `socket`、`connect`、`accept/accept4`、`ptrace`、`prctl`、`sendto/recvfrom`、
  `sendmsg/recvmsg`、`getsockopt`、`fcntl`、`memfd_create`、`ioctl`、`mmap`、
  `renameat/renameat2`、`unlinkat` 提供返回结果。
- 配对调用会产生入口和返回两条记录，`counts`、summary 和 callsite 频次统计的是
  **事件记录数**，不能直接当成 syscall 调用次数。read 在入口不回溯、不读取输出
  缓冲区，完整回溯和数据只在返回时采集；其他配对调用的完整回溯在入口记录。
- 发送数据在入口观察；接收数据在成功返回后观察，长度不超过返回值和缓冲区容量。
  数据预览最多 128 字节，向量 I/O 最多检查 8 个 iovec；预览不是完整请求或响应。
  KPM 1.8.1 起普通读写使用 `data[N/M] hex=... ascii="..."` 紧凑预览，hex 保留
  全部已预览字节，ASCII 中不可打印字节显示为点，引号与反斜杠转义；移除重复排版，
  不改变事件数量、回溯深度或 128 字节上限。旧预览文本仍能查询。
  用户内存读取为 best effort，其他线程并发修改缓冲区时不能保证与内核实际使用的
  字节完全相同。`unavailable_tail` / `msg_unavailable` 表示无法读取。
- `getsockopt(SOL_SOCKET, SO_ERROR)` 在成功返回且缓冲区足够时输出 `SO_ERROR`。
  非阻塞 connect 的 `-EINPROGRESS` 仅表示 pending，不能解释成连接成功。

`events[].fd_provenance` 是离线重建的已观察关联：

- `fd` 是该次操作的描述符，成功创建 fd 的返回事件使用真实返回值；
  `resource` 包含已观察的文件路径或 socket 对端，未知时为 null。
- `confidence=observed` 表示来自已采集的创建/连接证据，不是内核 fd 表快照；
  `confidence=unknown` 不表示该 fd 不存在。文件路径保留 openat 的原始路径和
  dirfd，不把相对路径猜成绝对路径。`resource.path_basis=openat` 明确表示打开时
  观察到的路径；重命名或删除后仍保留这个历史路径，不代表文件当前名称。
- `ioctl` 使用第一个参数的 fd；文件 `mmap` 使用第五个参数的 fd，匿名映射忽略
  fd 并保持未知。映射失败时文件关联只说明尝试对象，不能据此宣称映射存在。
- 关联跨 syscall 查询过滤保留，`--contains` 也匹配关联的路径和对端。
  必须采集 `close` 才启用跨事件关联。序列缺口、解析损坏、观察到的关闭/复用、
  未配对返回、进程生命周期变化会使相关关联失效。未捕获的 dup/close_range、
  跨进程共享文件表和描述符传递无法完整重建，因此不要将 observed 当成完整证明。
  recvmsg 出现未解码辅助数据时清空关联，避免推断 SCM_RIGHTS 传入的 fd。

## 事件时间与日志对齐

KPM 1.8+ 的 `events[].monotonic_ns` 是设备 `CLOCK_MONOTONIC` 纳秒值，在 hook
过滤通过后、参数解码和缓冲写入前采样。它标记观察时刻；入口与返回间隔包含
采集开销，不是无干扰的 syscall 性能测量。该时钟不计设备休眠时间，不等于 UTC
或 `CLOCK_BOOTTIME`。并发线程可能使序号顺序与时间戳顺序不同。

binary v2 保留 284 字节固定头与描述字段，利用头尾原保留的 u16 扩展位 0 标记
描述后附加的 8 字节时间戳。旧 v1/v2 记录没有扩展时，`monotonic_ns=null`，
不能根据序号或会话开始时间补造事件时间。

`status.clock` 及 manifest 中 `module.initial_status.clock` / `final_status.clock`
保存 `monotonic_before_ns`、`realtime_ns`、`monotonic_after_ns`。设备实时时钟在
两次单调采样之间读取。若该期间没有调时或休眠，可用以下区间估计设备 UTC：

```text
event.monotonic_ns + realtime_ns - monotonic_after_ns
到 event.monotonic_ns + realtime_ns - monotonic_before_ns
```

采样区间宽度是配对误差范围，不保证整场采集的绝对时间精度。先比较首尾采样的
时钟偏移；调时、休眠或时钟漂移会使它变化，不要跨变化强行套用同一偏移。
与主机抓包对齐前还需确认两台设备的时钟差；此处没有自动校准主机时钟。
时间相近也不能单独证明文件内容进入了某个请求。

## Hook 安装与监控状态

KPM 保留 75 个具有静态参数数量和返回处理方式的 hook 表项。加载模块时不安装
syscall hook；`capture` 停止并排空上一轮采集后，首次选中的 hook 才安装。
已安装项在后续采集中复用，直到模块卸载才移除。切换集合只改变记录范围，不卸载
先前安装的 hook。支持 75 个不代表每轮都安装或记录 75 个。

配置会先验证完整请求，再安装缺少的项，全部成功后才替换采集集合。格式错误、不支持的
编号或安装失败不会改变原来的采集集合；失败前已安装成功的 hook 保留复用，监控
保持关闭。监控正在运行时拒绝重新配置。控制请求并发时返回 `KPM_CONTROL_BUSY`，
待现有命令结束后重试。

`status` 区分三种集合：

- `hooks_supported` / `supported_nrs`：支持的静态白名单。
- `hooks_installed` / `installed_nrs`：实际已安装的 hook。
- `nrs_logging` / `logging_nrs`：选中准备记录的 syscall；是否正在记录还取决于
  `enabled`。停止采集后这些选择仍保留，但 `enabled=false`。

`manifest.module.initial_status` 保存本次配置前的状态，`final_status` 保存收尾
状态。安装失败返回 `KPM_HOOK_INSTALL_FAILED` 和 `syscall_nr`；不支持的编号返回
`SYSCALL_UNSUPPORTED`。主机要求新采集使用 KPM 1.8.0+，旧会话仍可离线查询。
