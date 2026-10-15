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
    pc: int = 0x1000,
    caller: int = 0x2000,
    version: int = EVENT_VERSION,
    flags: int = 0,
    entry_seq: int = 0,
    args: tuple[int, ...] = tuple(range(6)),
    monotonic_ns: int | None = None,
) -> bytes:
    max_backtrace = 7 if version == 1 else 16
    fixed_size = 212 if version == 1 else FIXED_RECORD_SIZE
    if len(backtrace) > max_backtrace:
        raise ValueError("fixture backtrace exceeds the protocol limit")
    if monotonic_ns is not None and version != 2:
        raise ValueError("timestamps require v2")
    trailer = struct.pack("<Q", monotonic_ns) if monotonic_ns is not None else b""
    length = fixed_size + len(desc) + len(trailer)
    fixed = struct.pack(
        f"<IHHIIiiii12QII{max_backtrace}Q16sHH",
        EVENT_MAGIC,
        version,
        flags,
        length,
        seq,
        nr,
        tgid,
        tid,
        uid,
        pc,
        caller,
        0x3000,
        0x4000,
        0,
        ret & 0xFFFFFFFFFFFFFFFF,
        *args,
        len(backtrace),
        entry_seq,
        *backtrace,
        *(0 for _ in range(max_backtrace - len(backtrace))),
        comm.ljust(16, b"\0"),
        len(desc),
        int(monotonic_ns is not None),
    )
    return fixed + desc + trailer


class ProtocolTests(unittest.TestCase):
    def test_parses_v1_event(self) -> None:
        stream = EventStream(make_event(ret=-2, version=1))
        events = list(stream)

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.seq, 1)
        self.assertEqual(event.nr, 56)
        self.assertIsNone(event.ret)
        self.assertEqual(event.ret_raw, (1 << 64) - 2)
        self.assertEqual(event.backtrace, (0x5000, 0x6000))
        self.assertIn("/proc/self/status", event.description)
        self.assertEqual(stream.quality()["invalid_records"], 0)

    def test_return_validity_does_not_infer_success_from_zero(self) -> None:
        for version, flags, nr, raw, expected in (
            (1, 0, 56, 0, None), (2, 0, 56, 0, None),
            (2, 1, 203, 0, None), (2, 2, 203, 0, 0),
            (2, 2, 56, -2, -2), (1, 0, 63, -9, -9),
            (2, 0, 63, 4, 4), (2, 3, 63, 0, None),
        ):
            with self.subTest(version=version, flags=flags, nr=nr):
                event = next(EventStream(make_event(version=version, flags=flags, nr=nr, ret=raw)))
                self.assertEqual(event.ret, expected)
                self.assertEqual(event.to_dict()["registers"]["ret_valid"], expected is not None)

    def test_pairs_return_with_entry_without_changing_record_layout(self) -> None:
        event = next(EventStream(make_event(flags=2, entry_seq=17, ret=4)))
        self.assertEqual(event.to_dict()["entry_seq"], 17)
        self.assertEqual(event.phase, "exit")
        self.assertEqual(event.ret, 4)

    def test_parses_v2_sixteen_frame_event(self) -> None:
        backtrace = tuple(0x5000 + index * 4 for index in range(16))

        stream = EventStream(make_event(backtrace=backtrace, version=2))
        events = list(stream)

        self.assertEqual(events[0].version, 2)
        self.assertEqual(events[0].backtrace, backtrace)

    def test_timestamp_extension_preserves_legacy_and_paired_records(self) -> None:
        records = (
            make_event(version=1), make_event(version=2),
            make_event(seq=3, flags=1, monotonic_ns=987654321012345),
            make_event(seq=4, flags=2, entry_seq=3, ret=-9, monotonic_ns=987654321012999),
        )
        events = list(EventStream(b"".join(records)))
        self.assertEqual([event.monotonic_ns for event in events],
                         [None, None, 987654321012345, 987654321012999])
        self.assertEqual(events[-1].to_dict()["monotonic_ns"], 987654321012999)
        self.assertEqual(events[-1].entry_seq, 3)
        self.assertEqual(events[-1].ret, -9)
        self.assertEqual(events[-1].description, events[0].description)
        # The pre-extension v2 layout still finds the same description bytes.
        self.assertEqual(records[-1][FIXED_RECORD_SIZE:-8], events[-1].description.encode())

    def test_timestamp_trailer_cannot_read_into_the_next_event(self) -> None:
        record = bytearray(make_event(monotonic_ns=42))
        del record[-8:]
        struct.pack_into("<I", record, 8, len(record))
        stream = EventStream(bytes(record) + make_event(seq=2, monotonic_ns=99))
        self.assertEqual([event.monotonic_ns for event in stream], [99])
        self.assertEqual(stream.invalid_records, 1)
        truncated = EventStream(make_event(monotonic_ns=42)[:-1])
        self.assertEqual(list(truncated), [])
        self.assertGreater(truncated.truncated_bytes, 0)

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
