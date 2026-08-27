# svcsite

English | [简体中文](README.zh-CN.md)

Android ARM64 syscall tracing and callsite analysis CLI for agents.

svcsite captures bounded syscall evidence from Android processes through ADB
and a KernelPatch Module (KPM). It resolves runtime addresses to mapped modules
and offsets for use in IDA, Ghidra, and other static analysis tools.

## Features

- Target one package or exact PID.
- Record syscall arguments, PC, LR, and up to 16 ARM64 return addresses.
- Return bounded events, ranked callsites, counts, and evidence quality.
- Provide deterministic JSON, stable error codes, and absolute artifact paths.

## Requirements

- macOS, Python 3.11+, and ADB
- Rooted Android ARM64 device with KernelPatch and `kpatch`
- KernelPatch SuperKey
- Android NDK r29+ to build the KPM

Validated on a Pixel 6 running Android 14 on arm64-v8a.

## Installation

```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Agent guidance is available in [`SKILL.md`](SKILL.md). Ensure `svcsite` is on
`PATH` before use.

## SuperKey

Store the SuperKey in a file with `0600` permissions:

```bash
mkdir -p ~/.config/svcsite
install -m 600 /dev/null ~/.config/svcsite/superkey
${EDITOR:-vi} ~/.config/svcsite/superkey
```

The CLI also accepts `SVCSITE_SUPERKEY_FILE` or `SVCSITE_SUPERKEY`. It keeps
the key out of command output, logs, and capture artifacts.

## Agent workflow

Use `--json` for Agent calls. stdout contains one JSON object, diagnostics go
to stderr, and failures return stable error codes with non-zero exit statuses.

Check the environment and module state:

```bash
svcsite doctor --device SERIAL --json
svcsite status --device SERIAL --json
```

Run one bounded capture:

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

Specify exactly one of `--package` and `--pid`. Package targets support
`attach`, `launch`, and `restart`; PID targets use exact TGID filtering in
`attach` mode.

Pass `--kpm` for the first load or an update. svcsite compares SHA-256 values
and skips installation when the device module already matches.

Query the saved session offline:

```bash
svcsite query /absolute/path/to/captures/SESSION_ID \
  --syscall openat,read \
  --contains /proc/ \
  --limit 20 \
  --json
```

`query` returns `events`, ranked `callsites`, `counts`, and `quality` in one
result. `--limit` bounds both returned lists. Use `--pid`, `--tid`,
`--contains`, or `--module-id` to narrow the evidence.

A completed capture disables monitoring and drains buffered events. After an
interruption, cleanup is safe to retry:

```bash
svcsite stop --device SERIAL --json
```

## Sessions and addresses

Each session contains `manifest.json`, `events.bin`, and process map snapshots
under `maps/`. Mapping failures are recorded as warnings; captured syscall
records remain queryable.

Raw LR and backtrace values are ARM64 return addresses. Derived callsites
subtract four bytes and expose the calling instruction as a module offset.
Use `module_id` or the full mapped path to identify a binary; `module` is a
display name.

## Development

```bash
make check
make kpm
```

## Safety and license

Use svcsite only for authorized security research and reverse engineering.
Loading a KPM changes live kernel state and can crash or reboot the device.

The KPM origin and modification boundary are documented in
[`UPSTREAM.md`](UPSTREAM.md). svcsite is licensed under the
[GNU General Public License v2.0 only](LICENSE).
