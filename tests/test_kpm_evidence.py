import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from svcsite.constants import SUPPORTED_SYSCALL_NUMBERS
from svcsite.protocol import EventStream

ROOT = Path(__file__).resolve().parents[1]


class KpmEvidenceTests(unittest.TestCase):
    def test_static_hook_arities_match_host_whitelist(self):
        source = (ROOT / "kpm/src/hook_table.h").read_text()
        tables = re.findall(
            r"static hook_entry_t hooks\[\] = \{(.*?)\n\};", source, re.DOTALL
        )
        entries = [
            (int(nr), int(arity))
            for table in tables
            for nr, arity in re.findall(r"\{\s*(\d+),\s*(\d+),", table)
        ]
        self.assertEqual(len(entries), len({nr for nr, _ in entries}))
        self.assertEqual({nr for nr, _ in entries}, SUPPORTED_SYSCALL_NUMBERS)
        for nr, arity in ((65, 3), (66, 3), (67, 4), (68, 4), (209, 5)):
            self.assertIn((nr, arity), entries)

    def test_actual_c_preview_handles_short_and_invalid_buffers(self):
        compiler = shutil.which("clang") or shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as directory:
            executable = str(Path(directory) / "io-preview-test")
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    "-I",
                    str(ROOT / "kpm/src"),
                    str(ROOT / "tests/io_preview_test.c"),
                    "-o",
                    executable,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [executable], check=True, capture_output=True, text=True
            )
            self.assertIn("checks passed", result.stdout)

    def test_actual_c_hook_configuration_is_lazy_and_preserves_failed_selection(self):
        compiler = shutil.which("clang") or shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable")
        source = (ROOT / "kpm/src/svcsite.c").read_text()
        start = source.index("static int prefer_fp_hook(")
        end = source.index(
            "/* ================================================================\n * Integer parser",
            start,
        )
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            (temporary / "hook_config.inc").write_text(source[start:end])
            executable = str(temporary / "hook-config-test")
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    "-I",
                    str(ROOT / "kpm/src"),
                    "-I",
                    directory,
                    str(ROOT / "tests/hook_config_test.c"),
                    "-o",
                    executable,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [executable], check=True, capture_output=True, text=True
            )
            self.assertIn("checks passed", result.stdout)

    def test_actual_c_serializer_preserves_timestamp_and_v2_offsets(self):
        compiler = shutil.which("clang") or shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable")
        source = (ROOT / "kpm/src/svcsite.c").read_text()
        type_start = source.index("typedef struct {\n    unsigned int seq;")
        type_end = source.index("} svc_event_t;", type_start) + len("} svc_event_t;")
        copy_start = source.index("static int copy_event_locked(")
        copy_end = source.index("static int peek_event(", copy_start)
        format_start = source.index("static int put_u16(")
        format_end = source.index("static struct file *open_event_file_fp(", format_start)
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            (temporary / "event_format.inc").write_text(
                source[type_start:type_end] + "\nstatic svc_event_t *g_events;\n"
                + source[copy_start:copy_end] + source[format_start:format_end]
            )
            executable = str(temporary / "event-format-test")
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-I", directory,
                 str(ROOT / "tests/event_format_test.c"), "-o", executable],
                check=True, capture_output=True,
            )
            result = subprocess.run([executable], check=True, capture_output=True)
            stream = EventStream(result.stdout)
            events = list(stream)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].monotonic_ns, 987654321012345)
            self.assertEqual(events[0].arguments[4], 3)
            self.assertEqual(events[0].ret, 0x8000)
            self.assertEqual(events[0].entry_seq, 6)
            self.assertEqual(events[0].backtrace, tuple(0x4000 + i * 4 for i in range(16)))
            self.assertEqual(events[0].description, "ret=32768")
            self.assertEqual(events[1].monotonic_ns, 0)
            self.assertEqual(len(events[1].description), 1023)
            self.assertEqual(stream.invalid_records, 0)
