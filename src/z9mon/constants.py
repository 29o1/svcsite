RESULT_SCHEMA = "z9mon.result.v1"
SESSION_SCHEMA = "z9mon.session.v1"
SUMMARY_SCHEMA = "z9mon.summary.v1"
MODULE_NAME = "z9null_monitor"
EVENT_PATH = "/data/local/tmp/z9null_monitor_events.bin"

KPATCH_CANDIDATES = (
    "/data/local/tmp/kpatch",
    "/data/adb/kpatch",
    "/data/adb/ap/bin/kpatch",
)

REVERSE_BASIC_SYSCALLS = (
    ("openat", 56),
    ("close", 57),
    ("read", 63),
    ("readlinkat", 78),
    ("newfstatat", 79),
    ("ptrace", 117),
    ("prctl", 167),
    ("socket", 198),
    ("connect", 203),
    ("sendto", 206),
    ("recvfrom", 207),
    ("munmap", 215),
    ("clone", 220),
    ("execve", 221),
    ("mmap", 222),
    ("mprotect", 226),
)

KNOWN_SYSCALLS = dict(REVERSE_BASIC_SYSCALLS)
KNOWN_SYSCALL_NAMES = {number: name for name, number in REVERSE_BASIC_SYSCALLS}

# These are the KPM's statically declared hooks.  The parameter count for each
# was reviewed in the module source; arbitrary syscall numbers are deliberately
# not dynamically hooked by the Agent-facing CLI.
TIER1_SYSCALL_NUMBERS = frozenset(
    (
        25, 29, 35, 48, 56, 57, 61, 62, 63, 64, 78, 79, 80, 93, 94, 97,
        105, 117, 129, 131, 134, 135, 144, 146, 147, 167, 198, 200, 203,
        206, 207, 214, 215, 220, 221, 222, 226, 232, 261, 268, 273, 277,
        279, 280, 291, 435,
    )
)
TIER2_SYSCALL_NUMBERS = frozenset(
    (
        5, 8, 21, 27, 34, 38, 39, 40, 53, 54, 98, 106, 201, 202, 208,
        210, 211, 212, 233, 242, 270, 271, 276, 281,
    )
)
SUPPORTED_SYSCALL_NUMBERS = TIER1_SYSCALL_NUMBERS | TIER2_SYSCALL_NUMBERS
