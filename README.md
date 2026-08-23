# svcsite

English | [简体中文](README.zh-CN.md)

Android ARM64 syscall tracing and callsite analysis CLI for agents.

svcsite captures runtime syscall evidence from target processes through ADB, a
root shell, and a KernelPatch Module (KPM), then resolves runtime addresses to
mapped modules and offsets. It provides reviewable dynamic evidence; symbol
recovery and decompilation remain the responsibility of static analysis tools.

## Capabilities

- Run bounded syscall captures by package name or exact PID.
- Record PC, LR, and up to 16 ARM64 frame-pointer-chain return addresses.
- Resolve callsites to `module_id` and `module_offset` using process maps.
- Return stable JSON, error codes, and absolute artifact paths to agents.

## Requirements

- Python 3.11+
- ADB
- An Android ARM64 device
- root, KernelPatch, `kpatch`, and a SuperKey
- Android NDK r29+ to build the KPM

The current validation baseline is a macOS host with a Pixel 6 running Android
14 on arm64-v8a.

## Installation

```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Agents can read the repository-level `SKILL.md` for invocation guidance. Make
sure `svcsite` is available on `PATH` at runtime.

## SuperKey

By default, svcsite reads the SuperKey from a file with `0600` permissions:

```bash
mkdir -p ~/.config/svcsite
install -m 600 /dev/null ~/.config/svcsite/superkey
${EDITOR:-vi} ~/.config/svcsite/superkey
```

Alternatively, set `SVCSITE_SUPERKEY_FILE` to another file or provide
`SVCSITE_SUPERKEY` as an environment variable. The CLI never prints the
SuperKey.

## Usage

Agents should always pass `--json`. In JSON mode, stdout contains exactly one
JSON object and diagnostics are written to stderr.

### 1. Check the environment

```bash
svcsite doctor --device SERIAL --json
svcsite status --device SERIAL --json
```

### 2. Capture

```bash
svcsite capture --device SERIAL --package io.example.target --duration 15 \
  --target-mode launch --output ./captures --kpm ./kpm/svcsite.kpm --json
```

Pass exactly one of `--package` and `--pid`. Package targets support `attach`,
`launch`, and `restart`. PID targets use exact TGID filtering and support only
`attach`.

Pass `--kpm` explicitly when loading the module for the first time or when the
device module is outdated. The CLI converges the deployed module against the
local file's SHA-256 and skips replacement when they already match. Once the
module matches, `--kpm` may be omitted.

The default capture uses a baseline syscall set intended for reverse
engineering. Use `--syscall` to narrow it further:

```bash
svcsite capture --device SERIAL --pid 1687 --duration 10 \
  --syscall openat,read,connect,sendto --json
```

Each capture creates an independent session:

```text
captures/SESSION_ID/
├── manifest.json
├── events.bin
└── maps/
    └── SNAPSHOT-PID.maps
```

`manifest.json` contains the capture parameters, summary, and warnings.
`events.bin` stores syscall evidence, and `maps/` supports address resolution.
A maps failure produces a warning but does not invalidate syscall evidence that
was already captured.

### 3. Query

```bash
svcsite query ./captures/SESSION_ID --syscall openat,read \
  --contains /proc/ --limit 20 --json
```

`query` is a read-only offline operation that returns:

- `events`: syscall, process, thread, argument, and backtrace evidence.
- `callsites`: syscall × module × module offset, ranked by frequency.
- `counts`: match, return, and truncation counts.
- `quality`: kernel drops, sequence gaps, and parser status.

`--limit` bounds both events and callsites. Use `--pid`, `--tid`, `--contains`,
or `--module-id` to narrow the result.

`module` is only a display name. Use `module_id` or the full `path` when
comparing mappings. Raw caller and backtrace values are ARM64 return addresses;
derived callsites subtract four bytes, so their `module_offset` can be passed
directly to IDA or another static analysis tool.

## Build and verification

```bash
make check
make kpm
```

`make check` runs Python syntax checks and unit tests. `make kpm` builds
`kpm/svcsite.kpm` from the pinned KernelPatch submodule.

## Safety and scope

Use this project only for authorized security research and reverse engineering.
Loading a KPM changes live kernel state and may crash or reboot the device. Use
a test device and back up important data first.

## Origin and license

The KPM was migrated from a locally modified version of
`XiaoWaaay/SVCMonitors`. See [UPSTREAM.md](UPSTREAM.md) for the pinned upstream
commit, attribution, and modification boundary.

svcsite is licensed under the [GNU General Public License v2.0 only](LICENSE).
