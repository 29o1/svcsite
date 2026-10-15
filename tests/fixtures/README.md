# Device evidence regression

`evidence_workload.c` exercises syscall return values, fd reuse, file/vector I/O,
UDP send/receive, truncated datagrams, invalid pointers and a nonblocking refused
TCP connection. It uses only loopback sockets and creates a PID-specific file
under `/data/local/tmp`, which it removes. The normal run prints 41 checks and
zero failures. The optional `blocked` mode checks a read spanning two captures.

Build using the Android NDK's `aarch64-linux-android26-clang` with
`-Wall -Wextra -Werror -O0 -g -fno-omit-frame-pointer`, then push the resulting
executable to `/data/local/tmp/svcsite-evidence-workload`. No APK is needed.

Explicitly converge `kpm/svcsite.kpm` using `capture --kpm /absolute/path/...`
before starting the timed workload. Start the executable with a 10-second delay
and capture its exact PID for 13 seconds with:

```text
--syscall openat,close,read,write,pread64,pwrite64,readv,writev,socket,connect,ptrace,prctl,sendto,recvfrom,sendmsg,recvmsg,getsockopt
```

Use `query SESSION --limit 100 --json` to verify paired entry/exit records,
negative errno results, source fd generations, SO_ERROR and bounded previews.
The normal workload produces 74 events on the Pixel 6 / Android 14 baseline;
runtime implementation differences may change incidental events. The truncated
recvmsg reports return length 6 and previews only the three bytes that fit.
A pre-stop maps warning is expected if the workload has already exited.

For generation isolation, start the workload with arguments `3 blocked`, then
immediately capture the same PID twice, for 5 and 8 seconds, selecting
`read,openat,close`. The first session should contain only the entry for a
7-byte read. Its completion belongs to the old capture and must not appear in
the second session. A fresh 1-byte read in the second session must have both
entry and exit records. The workload prints six checks and zero failures.
Adjust delays on slower hosts while retaining this ordering; the CLI's attach
setup occurs before its duration timer begins.

After each capture, check `enabled=false`, `events_buffered=0` and all loss/parser
metrics. Remove the temporary device executable and output files after saving
results. Native host tests in `test_kpm_evidence.py` separately run the actual
scatter/gather preview code with ASan/UBSan and invalid/truncated buffers.

## Registration state and clocks

`registration_workload.c` uses PID-specific temporary files and a read-only
`BINDER_VERSION` query on `/dev/binder`. Build with the same NDK flags above.
Run with a 5-second delay and capture its exact PID for 8 seconds using the
25-call device-registration recipe from `SKILL.md`. Explicitly converge the
current KPM before starting the delayed workload. It retains the process for
10 seconds after printing JSON so the final maps snapshot can succeed.

The JSON contains operation assertions, file/Binder fds, the original path,
the actual mmap result, a userspace monotonic interval around that mmap, and
a realtime/monotonic calibration sample. Query with `--limit 100` and verify:

- File mmap entry/return timestamps fall inside the userspace interval; the
  return address matches and the fd points to the observed file.
- Anonymous mmap ignores its fd; invalid-fd mmap returns `-EBADF`.
- Binder ioctl pairs with success and `/dev/binder`; invalid/file ioctls retain
  actual errors. The ioctl payload is not decoded into application semantics.
- renameat, renameat2 and unlinkat each have success and `-ENOENT` pairs.
- Post-rename file operations retain the open-time path and `path_basis=openat`.
- Kernel status calibration agrees with the userspace clock sample within the
  observed intervals plus any clock adjustment; all loss/parser metrics are zero.

Remove the temporary executable and JSON/stderr files after preserving results.
