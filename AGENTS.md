# Z9Null Monitor CLI agent instructions

## Scope

This project exposes Android ARM64 syscall evidence through a deterministic
CLI. It does not wrap other reverse-engineering tools and does not embed an
LLM.

## Target environment

- Host: macOS
- Python: 3.11+
- Device baseline: Pixel 6, Android 14, arm64-v8a
- Transport: ADB
- Privilege/module layer: root shell, kpatch, KernelPatch KPM

## Command contract

- Use `--json` for Agent calls.
- stdout must contain exactly one JSON object in JSON mode.
- Diagnostics belong on stderr.
- Errors require stable `code` values and non-zero exit codes.
- Never print, log, or place the SuperKey in an artifact.
- Return absolute paths for generated artifacts.
- Keep event queries bounded by a caller-provided limit.
- `status` and `stop` should be safe to retry.
- Module loading must remain an explicit operation.
- Treat `capture` as the task-level write operation and `query` as read-only.
- A capture must finish with monitoring disabled and `events_buffered == 0`.
- Capture maps for every process under the target UID after launch and before
  stop. Maps failures are warnings and must not invalidate syscall evidence.
- Prefer `query --stats` or a narrow `query --limit N` over reading
  `events.bin` directly.
- Preserve raw runtime addresses. Resolved module/base/offset fields are
  additive, and sessions without `modules.json` remain queryable.
- Custom syscall selection is restricted to KPM Tier1/Tier2 hooks with a
  statically declared arity; handle `SYSCALL_UNSUPPORTED` rather than retrying
  arbitrary syscall numbers.

## Development commands

```bash
make check
make kpm
```

Run device checks without modifying monitor state:

```bash
PYTHONPATH=src python3 -m z9mon doctor --device SERIAL --json
PYTHONPATH=src python3 -m z9mon status --device SERIAL --json
```

Run one bounded capture:

```bash
PYTHONPATH=src python3 -m z9mon capture \
  --device SERIAL \
  --package TARGET \
  --duration 15 \
  --preset reverse-basic \
  --launch \
  --output ./captures \
  --json
```

If the module is absent, report `MODULE_NOT_LOADED`; only use
`--load-module /absolute/path/to/z9null_monitor.kpm` when module replacement was
requested. Explicit module loading has a minimum 60-second per-command wait
because it installs kernel hooks; `stop`, `capture`, and module loading affect
device state.

Read a bounded result:

```bash
PYTHONPATH=src python3 -m z9mon query \
  /absolute/path/to/SESSION \
  --syscall openat,read \
  --contains /proc/ \
  --limit 50 \
  --json
```

Capture artifacts are `manifest.json`, `events.bin`, `summary.json`,
`modules.json`, and raw snapshots under `maps/`.
JSONL is produced only by `query --format jsonl`.

Resolve one address without modifying device state:

```bash
PYTHONPATH=src python3 -m z9mon address resolve \
  /absolute/path/to/SESSION \
  --pid PID \
  --address 0xADDRESS \
  --json
```

## Source boundaries

- `src/z9mon/`: host-side Python implementation.
- `kpm/`: locally modified KPM derived from the upstream documented in
  `UPSTREAM.md`.
- `KernelPatch/`: pinned upstream Git submodule; do not edit it locally.

Do not migrate the legacy Android UI or PC Web Viewer into this repository.
