import struct
from pathlib import Path
import tempfile
import unittest

from svcsite.protocol import (
    EVENT_MAGIC,
    EVENT_VERSION,
    FIXED_RECORD_SIZE,
    EventStream,
    open_event_stream,
)


def make_event(
    *,
    seq: int = 1,
    nr: int = 56,
    tgid: int = 100,
    tid: int = 101,
    uid: int = 10234,
    ret: int = 0,
    comm: bytes = b"fixture",
    desc: bytes = b'path="/proc/self/status"',
    backtrace: tuple[int, ...] = (0x5000, 0x6000),
    version: int = EVENT_VERSION,
) -> bytes:
    max_backtrace = 7 if version == 1 else 16
    fixed_size = 212 if version == 1 else FIXED_RECORD_SIZE
    if len(backtrace) > max_backtrace:
        raise ValueError("fixture backtrace exceeds the protocol limit")
    length = fixed_size + len(desc)
    fixed = struct.pack(
        f"<IHHIIiiii12QII{max_backtrace}Q16sHH",
        EVENT_MAGIC,
        version,
        0,
        length,
        seq,
        nr,
        tgid,
        tid,
        uid,
        0x1000,
        0x2000,
        0x3000,
        0x4000,
        0,
        ret & 0xFFFFFFFFFFFFFFFF,
        *range(6),
        len(backtrace),
        0,
        *backtrace,
        *(0 for _ in range(max_backtrace - len(backtrace))),
        comm.ljust(16, b"\0"),
        len(desc),
        0,
    )
    return fixed + desc


class ProtocolTests(unittest.TestCase):
    def test_parses_v1_event(self) -> None:
        stream = EventStream(make_event(ret=-2, version=1))
        events = list(stream)

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.seq, 1)
        self.assertEqual(event.nr, 56)
        self.assertEqual(event.ret, -2)
        self.assertEqual(event.backtrace, (0x5000, 0x6000))
        self.assertIn("/proc/self/status", event.description)
        self.assertEqual(stream.quality()["invalid_records"], 0)

    def test_parses_v2_sixteen_frame_event(self) -> None:
        backtrace = tuple(0x5000 + index * 4 for index in range(16))

        stream = EventStream(make_event(backtrace=backtrace, version=2))
        events = list(stream)

        self.assertEqual(events[0].version, 2)
        self.assertEqual(events[0].backtrace, backtrace)

    def test_resynchronizes_after_corrupt_bytes(self) -> None:
        stream = EventStream(b"noise" + make_event(seq=9))
        events = list(stream)

        self.assertEqual(events[0].seq, 9)
        self.assertEqual(stream.skipped_bytes, 5)

    def test_reports_truncated_record(self) -> None:
        record = make_event()
        stream = EventStream(record[:-4])
        events = list(stream)

        self.assertEqual(events, [])
        self.assertEqual(stream.truncated_bytes, len(record) - 4)

    def test_streams_file_without_materializing_parse_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "events.bin")
            path.write_bytes(make_event(seq=1) + make_event(seq=2))

            with open_event_stream(path) as stream:
                sequences = [event.seq for event in stream]
                quality = stream.quality()

        self.assertEqual(sequences, [1, 2])
        self.assertEqual(quality["events"], 2)
        self.assertEqual(quality["invalid_records"], 0)


if __name__ == "__main__":
    unittest.main()
