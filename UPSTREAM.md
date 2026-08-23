# Upstream provenance

This repository contains a locally modified KPM derived from:

- Upstream repository: <https://github.com/XiaoWaaay/SVCMonitors>
- Upstream base commit: `25b30cf5b2ddbb9b523c48d14a65a9f9877e1719`
- Local derivative checkpoint: `6b5fca1c1f07867b450b41c8dde999c60bc6c21f`
- Original KPM author recorded by the source: `Xiaowaaa`
- Local derivative author: `z9null`

The migrated KPM files are:

- `kpm/src/svcsite.c`
- `kpm/Makefile`

The local version renamed `svc_monitor.c` to `svcsite.c` and added
KernelPatch API compatibility fixes, expanded event buffering, binary event
output, additional syscall argument decoding, and Android-side control
compatibility. Migrated text files use LF line endings; this normalization does
not change KPM behavior.

The host-side Python package under `src/svcsite/`, command contract, and
Agent-facing documentation are new work in this repository.

This repository's KPM `1.1.0` added stop-and-drain behavior and a small `sysnr`
lookup command. KPM `1.2.0` keeps PC and LR in their dedicated event fields,
uses all seven backtrace slots for distinct FP-chain return addresses, and
leaves the binary v1 record layout unchanged. KPM `1.3.0` expands the FP-chain
to 16 return addresses and writes binary v2 records; the host parser retains
binary v1 compatibility.

## KernelPatch

KernelPatch is included as a Git submodule from:

- <https://github.com/bmax121/KernelPatch>
- Pinned commit: `55c439fa4d9c945ceeb57a3610b8a9a988647cb5`
- License: GPL-2.0 as declared by that upstream repository

KernelPatch remains a separate repository with its own history and license.

## License

The source repository did not contain a root-level project license when this
derivative was migrated. Its KPM source declares `KPM_LICENSE("GPL v2")`.
This repository distributes the derivative and the host-side implementation
under `GPL-2.0-only`; the root `LICENSE` contains the complete license text.
Preserve this provenance record in redistributed copies.
