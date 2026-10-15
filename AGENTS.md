# svcsite CLI agent instructions

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
- Module loading must remain explicit. `--kpm` converges and skips replacement
  when the deployed sha256 already matches.
- Treat `capture` as the task-level write operation and `query` as read-only.
- Keep the Agent-facing command set to `doctor`, `status`, `stop`, `capture`,
  and `query`.
- A capture must finish with monitoring disabled and `events_buffered == 0`.
- Capture accepts exactly one of package or PID. PID targets are attach-only;
  filtering is exact at the KPM TGID layer. Capture maps for every process
  under a package target, or the exact PID for a PID target,
  after start and before stop. Maps failures are warnings and must not
  invalidate syscall evidence.
- Prefer a narrow `query --limit N` over reading `events.bin` directly.
- Query always returns bounded `events`, ranked `callsites`, counts, and
  evidence quality in one result. The default limit is 20 and applies to both
  returned lists.
- Use `query --module-id MODULE_ID` to filter events and callsites to one exact
  mapped binary.
- Preserve raw runtime addresses. Resolved module/path/offset fields are
  additive, and sessions without mapping data remain queryable.
- Preserve raw ARM64 return addresses. Derived callsites subtract four bytes
  and remain additive; do not treat the syscall PC itself as a return address.
- Keep binary v1 sessions readable while new captures use binary v2 with up to
  16 FP-chain return addresses.
- Treat `module` as a display name only. Use `module_id` or the full `path`
  when comparing mappings because unrelated APKs and libraries can share a
  basename.
- Custom syscall selection is restricted to the KPM static hook table with a
  statically declared arity; handle `SYSCALL_UNSUPPORTED` rather than retrying
  arbitrary syscall numbers.
- Bench is development tooling outside the main Agent CLI.

## Development commands

```bash
make check
make kpm
```

Run device checks without modifying monitor state:

```bash
PYTHONPATH=src python3 -m svcsite doctor --device SERIAL --json
PYTHONPATH=src python3 -m svcsite status --device SERIAL --json
```

Run one bounded capture:

```bash
PYTHONPATH=src python3 -m svcsite capture \
  --device SERIAL \
  --package TARGET \
  --duration 15 \
  --target-mode launch \
  --output ./captures \
  --json
```

If the module is absent or outdated, report the stable error and use
`--kpm /absolute/path/to/svcsite.kpm` to converge. Explicit module
loading has a minimum 60-second per-command wait because it installs kernel
hooks; `stop`, `capture`, and module loading affect device state.

Benchmark the current build against a controlled workload:

```bash
PYTHONPATH=src python3 -m tools.svcsite_bench run \
  --device SERIAL \
  --kpm /absolute/path/to/svcsite.kpm \
  --json
```

Compare two bench reports (offline, read-only):

```bash
PYTHONPATH=src python3 -m tools.svcsite_bench compare \
  /absolute/path/to/bench/OLD_RUN/report.json \
  /absolute/path/to/bench/NEW_RUN/report.json \
  --json
```

Read a bounded result:

```bash
PYTHONPATH=src python3 -m svcsite query \
  /absolute/path/to/SESSION \
  --syscall openat,read \
  --contains /proc/ \
  --limit 50 \
  --json
```

Capture artifacts are `manifest.json`, `events.bin`, and raw snapshots under
`maps/`. Capture summary data lives in `manifest.json`. Query resolves the raw
`maps/` snapshots internally; legacy sessions that carry `modules.json` remain
readable.

## Source boundaries

- `src/svcsite/`: host-side Python implementation.
- `kpm/`: locally modified KPM derived from the upstream documented in
  `UPSTREAM.md`.
- `KernelPatch/`: pinned upstream Git submodule; do not edit it locally.

Do not migrate the legacy Android UI or PC Web Viewer into this repository.
