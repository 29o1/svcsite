RESULT_SCHEMA = "svcsite.result.v1"
SESSION_SCHEMA = "svcsite.session.v2"
MODULES_SCHEMA = "svcsite.modules.v1"
LEGACY_MODULES_SCHEMA = "z9mon.modules.v1"
MODULE_NAME = "svcsite"
LEGACY_MODULE_NAME = "z9null_monitor"
EVENT_PATH = "/data/local/tmp/svcsite_events.bin"
DEPLOYED_MARKER_PATH = "/data/local/tmp/svcsite.deployed.sha256"

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

# The KPM has a statically reviewed arity for exactly these hooks. Arbitrary
# syscall numbers are deliberately not dynamically hooked by the Agent CLI.
SUPPORTED_SYSCALL_NUMBERS = frozenset(
    (
        5, 8, 21, 25, 27, 29, 34, 35, 38, 39, 40, 48, 53, 54, 56, 57, 61,
        62, 63, 64, 78, 79, 80, 93, 94, 97, 98, 105, 106, 117, 129, 131,
        134, 135, 144, 146, 147, 167, 198, 200, 201, 202, 203, 206, 207,
        208, 210, 211, 212, 214, 215, 220, 221, 222, 226, 232, 233, 242,
        261, 268, 270, 271, 273, 276, 277, 279, 280, 281, 291, 435,
    )
)
