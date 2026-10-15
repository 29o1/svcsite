import json
import tempfile
import unittest
from pathlib import Path

from test_protocol import make_event

from svcsite.query import run_query


class FdProvenanceTests(unittest.TestCase):
    def query(self, records, *, close=True, **filters):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "events.bin").write_bytes(b"".join(records))
            (root / "manifest.json").write_text(
                json.dumps(
                    {
                        "capture": {
                            "syscalls": [
                                {"nr": nr, "name": name}
                                for nr, name in (
                                    (56, "openat"),
                                    (63, "read"),
                                    *(([(57, "close")]) if close else []),
                                )
                            ]
                        },
                        "summary": {"kernel_dropped": 0},
                    }
                )
            )
            options = {
                "syscalls": (),
                "pid": None,
                "tid": None,
                "contains": None,
                "limit": 50,
            }
            options.update(filters)
            return run_query(session=root, **options)

    @staticmethod
    def event(
        seq,
        nr,
        *,
        flags=2,
        ret=0,
        entry=0,
        fd=3,
        desc=b"",
        tid=101,
        pid=100,
        arg1=0,
        arg2=0,
    ):
        return make_event(
            seq=seq,
            nr=nr,
            flags=flags,
            ret=ret,
            entry_seq=entry,
            tgid=pid,
            tid=tid,
            desc=desc,
            args=(fd, arg1, arg2, 0, 0, 0),
        )

    def opened(self, path=b"/proc/self/status"):
        return [
            self.event(1, 56, flags=1, desc=b'path="' + path + b'" flags=0'),
            self.event(2, 56, entry=1, ret=3),
        ]

    def test_filtered_read_uses_creator_outside_filter(self):
        result = self.query(
            self.opened()
            + [self.event(3, 63, flags=1), self.event(4, 63, entry=3, ret=4)],
            syscalls=("read",),
            contains="/proc/",
            limit=1,
        )
        self.assertEqual(result["counts"]["matched"], 2)
        self.assertEqual(
            result["events"][0]["fd_provenance"]["resource"]["path"],
            "/proc/self/status",
        )

    def test_close_failure_and_reuse_do_not_keep_old_path(self):
        events = self.opened() + [
            self.event(3, 57, flags=1),
            self.event(4, 57, entry=3, ret=-5),
            self.event(5, 63, ret=1),
            self.event(6, 56, flags=1, desc=b'path="/new" flags=0'),
            self.event(7, 56, entry=6, ret=3),
            self.event(8, 63, flags=1),
            self.event(9, 63, entry=8, ret=1),
        ]
        reads = self.query(events, syscalls=("read",))["events"]
        self.assertIsNone(reads[0]["fd_provenance"]["resource"])
        self.assertEqual(reads[-1]["fd_provenance"]["resource"]["path"], "/new")

    def test_gap_corruption_and_missing_lifecycle_invalidate(self):
        for records, close in (
            (self.opened() + [self.event(4, 63)], True),
            (self.opened() + [b"corrupt", self.event(3, 63)], True),
            (self.opened() + [self.event(3, 63)], False),
        ):
            with self.subTest(close=close, records=len(records)):
                event = self.query(records, close=close, syscalls=("read",))["events"][
                    0
                ]
                self.assertEqual(event["fd_provenance"]["confidence"], "unknown")

    def test_attach_missing_pair_failed_open_and_process_isolation(self):
        events = self.opened() + [
            self.event(3, 63, pid=200),
            self.event(4, 56, flags=1, desc=b'path="/absent" flags=0'),
            self.event(5, 56, ret=-2, entry=4),
            self.event(6, 63, fd=8),
            self.event(7, 198, ret=3, entry=999),
            self.event(8, 63),
        ]
        result = self.query(events)["events"]
        for index in (2, 5, 7):
            self.assertIsNone(result[index]["fd_provenance"]["resource"])
        self.assertIsNone(result[4]["fd_provenance"]["fd"])

    def test_nonblocking_connect_requires_matching_so_error(self):
        events = [
            self.event(1, 203, flags=1, desc=b"sockfd=3 AF_INET 127.0.0.1:1234"),
            self.event(2, 203, ret=-115, entry=1),
            self.event(3, 209, flags=1, arg1=1, arg2=4),
            self.event(4, 209, entry=3, arg1=1, arg2=4, desc=b"ret=0 SO_ERROR=0"),
            self.event(5, 64, flags=1),
            self.event(6, 64, entry=5, ret=2),
        ]
        result = self.query(events)["events"]
        self.assertEqual(
            result[1]["fd_provenance"]["resource"]["connection"], "pending"
        )
        self.assertEqual(
            result[3]["fd_provenance"]["resource"]["connection"], "connected"
        )
        self.assertEqual(
            result[-1]["fd_provenance"]["resource"]["peer"], "AF_INET 127.0.0.1:1234"
        )

    def test_interleaved_threads_preserve_original_operation_resource(self):
        events = self.opened() + [
            self.event(3, 65, flags=1),
            self.event(4, 57, flags=1, tid=102),
            self.event(5, 57, tid=102, entry=4),
            self.event(6, 65, entry=3, ret=2),
            self.event(7, 63),
        ]
        result = self.query(events)["events"]
        self.assertIsNone(result[-2]["fd_provenance"]["resource"])
        self.assertIsNone(result[-1]["fd_provenance"]["resource"])

    def test_failed_reconnect_and_unpaired_return_cannot_reuse_peer(self):
        events = [
            self.event(1, 203, flags=1, desc=b"sockfd=3 AF_INET 127.0.0.1:1234"),
            self.event(2, 203, entry=1),
            self.event(3, 203, flags=1, desc=b"sockfd=3 AF_INET 127.0.0.1:4567"),
            self.event(4, 203, entry=3, ret=-111),
            self.event(5, 64, flags=1),
            self.event(6, 64, entry=5, ret=-32),
        ]
        result = self.query(events)["events"]
        self.assertIsNone(result[3]["fd_provenance"]["resource"])
        self.assertIsNone(result[-1]["fd_provenance"]["resource"])

    def test_partial_entry_and_control_transfers_do_not_invent_resources(self):
        for tail in (
            [
                self.event(3, 56, flags=1, desc=b'path="truncated'),
                self.event(4, 56, entry=3, ret=3),
            ],
            [
                self.event(3, 212, flags=1),
                self.event(
                    4, 212, entry=3, desc=b"ret=1 control_bytes=24 control_not_decoded"
                ),
            ],
        ):
            result = self.query(
                self.opened()
                + tail
                + [self.event(5, 63, flags=1), self.event(6, 63, entry=5, ret=1)]
            )
            self.assertIsNone(result["events"][-1]["fd_provenance"]["resource"])

    def test_ioctl_and_file_mmap_use_observed_open_path(self):
        for nr, args in ((29, (3, 0xc0306201, 0x9000, 0, 0, 0)),
                         (222, (0, 4096, 1, 1, 3, 0))):
            with self.subTest(nr=nr):
                records = self.opened(b"/data/registration") + [
                    make_event(seq=3, nr=nr, flags=1, args=args, monotonic_ns=100),
                    make_event(seq=4, nr=nr, flags=2, entry_seq=3,
                               ret=0x8000 if nr == 222 else 0, args=args, monotonic_ns=200),
                ]
                result = self.query(records, syscalls=(str(nr),), contains="registration")
                self.assertEqual(result["counts"]["matched"], 2)
                for event in result["events"]:
                    self.assertEqual(event["fd_provenance"]["fd"], 3)
                    self.assertEqual(event["fd_provenance"]["resource"]["path_basis"], "openat")
                self.assertEqual(result["events"][-1]["monotonic_ns"], 200)
                self.assertEqual(result["events"][-1]["registers"]["ret"],
                                 0x8000 if nr == 222 else 0)

    def test_anonymous_mmap_ignores_fd_and_close_invalidates_pending_mapping(self):
        anonymous = (0, 4096, 3, 0x22, 3, 0)
        file_mapping = (0, 4096, 1, 1, 3, 0)
        records = self.opened() + [
            make_event(seq=3, nr=222, flags=1, args=anonymous),
            make_event(seq=4, nr=222, flags=2, args=anonymous, entry_seq=3, ret=0x8000),
            make_event(seq=5, nr=222, flags=1, args=file_mapping),
            self.event(6, 57, flags=1, tid=102),
            self.event(7, 57, entry=6, tid=102),
            make_event(seq=8, nr=222, flags=2, args=file_mapping, entry_seq=5, ret=-9),
        ]
        result = self.query(records)["events"]
        for index in (2, 3, 7):
            self.assertIsNone(result[index]["fd_provenance"]["resource"])
        self.assertEqual(result[2]["fd_provenance"]["fd"], -1)
        self.assertEqual(result[4]["fd_provenance"]["resource"]["path"], "/proc/self/status")

    def test_rename_does_not_relabel_historical_open_path(self):
        records = self.opened(b"/data/old") + [
            self.event(3, 38, flags=1, desc=b'oldpath="/data/old" newpath="/data/new"'),
            self.event(4, 38, entry=3),
            self.event(5, 29, flags=1),
            self.event(6, 29, entry=5, ret=-25),
        ]
        result = self.query(records)["events"][-1]["fd_provenance"]
        self.assertEqual(result["resource"]["path"], "/data/old")
        self.assertEqual(result["resource"]["path_basis"], "openat")
