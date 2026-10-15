#include <assert.h>
#include <stdio.h>
#include <string.h>
#define MAX_BT 16
#define DESC_BUF_SIZE 1024
/* Actual production event type, copy and serializer, extracted by the host test. */
#include "event_format.inc"

int main(void) {
    svc_event_t event = {0}, copied;
    unsigned char bytes[2048];
    event.seq = 7; event.nr = 222; event.tgid = 100; event.pid = 101;
    event.a4 = 3; event.ret = 0x8000; event.event_flags = 2; event.entry_seq = 6;
    event.monotonic_ns = 987654321012345ULL;
    event.bt_depth = 16;
    for (int i = 0; i < 16; i++) event.bt[i] = 0x4000 + i * 4;
    strcpy(event.comm, "clock-fixture");
    strcpy(event.desc, "ret=32768");
    g_events = &event;
    assert(copy_event_locked(&copied, 0));
    assert(copied.monotonic_ns == event.monotonic_ns);
    int length = format_event_bin(bytes, sizeof(bytes), &copied);
    assert(length == 284 + (int)strlen(event.desc) + 8);
    for (int size = 0; size < length; size++)
        assert(format_event_bin(bytes, size, &copied) == 0);
    assert(format_event_bin(bytes, length, &copied) == length);
    assert(fwrite(bytes, 1, length, stdout) == (size_t)length);
    memset(event.desc, 'x', sizeof(event.desc) - 1);
    event.desc[sizeof(event.desc) - 1] = 0;
    event.monotonic_ns = 0; /* Zero is a known timestamp, not a missing extension. */
    length = format_event_bin(bytes, sizeof(bytes), &event);
    assert(length == 284 + 1023 + 8);
    assert(fwrite(bytes, 1, length, stdout) == (size_t)length);
    return 0;
}
