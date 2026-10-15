#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define DATA_PREVIEW 128
static unsigned long valid_start, valid_end;
static int reads;
static int is_user_addr(unsigned long p) { return p >= valid_start && p < valid_end; }
static int safe_copy_user_bytes(char *out, unsigned long p, int n) {
    reads++;
    if (!is_user_addr(p) || n < 0 || (unsigned long)n > valid_end - p) return 0;
    memcpy(out, (void *)p, n);
    return n;
}
static int parse_sockaddr(char *buf, int size, unsigned long p, int n) {
    (void)p;
    return snprintf(buf, size, "address_bytes=%d", n);
}
#include "io_preview.h"
int main(void) {
    struct {
        struct svc_iovec vec[16];
        struct svc_msghdr msg;
        unsigned char data[256];
    } input = {0};
    char out[1024];
    valid_start = (unsigned long)&input;
    valid_end = valid_start + sizeof(input);
    memset(input.data, 'A', sizeof(input.data));
    /* Every byte remains recoverable from compact hex, including NUL/escapes. */
    for (int i = 0; i < 128; i++) input.data[i] = (unsigned char)i;
    int n = data_preview(out, sizeof(out), (unsigned long)input.data, 128);
    assert(n == (int)strlen(out) && n < 450);
    assert(strstr(out, "data[128/128] hex="));
    const char *encoded = strstr(out, "hex=") + 4;
    for (int i = 0; i < 128; i++) {
        unsigned int byte;
        assert(sscanf(encoded + i * 2, "%2x", &byte) == 1 && byte == input.data[i]);
    }
    assert(!strncmp(encoded + 256, " ascii=", 7));
    for (int size = 0; size <= 1024; size++) {
        char guarded[1026];
        memset(guarded, 'Z', sizeof(guarded));
        n = data_preview(guarded + 1, size, (unsigned long)input.data, ~0UL);
        assert(guarded[0] == 'Z' && guarded[size + 1] == 'Z');
        if (n) assert(n < size && guarded[n + 1] == 0);
    }
    reads = 0;
    data_preview(out, sizeof(out), 0, 128);
    assert(!strcmp(out, "buf=0x0") && reads == 0);
    data_preview(out, sizeof(out), (unsigned long)input.data, 0);
    assert(reads == 0);
    memset(input.data, 'A', sizeof(input.data));
    data_preview(out, sizeof(out), (unsigned long)input.data, 3);
    assert(strstr(out, "data[3/3] hex=414141 ascii=\"AAA\""));
    input.vec[0] = (struct svc_iovec){(unsigned long)input.data, 2};
    input.vec[1] = (struct svc_iovec){(unsigned long)input.data + 2, 254};
    preview_iov(out, sizeof(out), (unsigned long)input.vec, 2, 3);
    assert(strstr(out, "preview_bytes=3 "));
    assert(strstr(out, "hex=414141") && !strstr(out, "hex=41414141"));
    preview_iov(out, sizeof(out), (unsigned long)input.vec, 2, ~0UL);
    assert(strstr(out, "preview_bytes=128 "));
    reads = 0;
    memset(input.vec, 0, sizeof(input.vec));
    preview_iov(out, sizeof(out), (unsigned long)input.vec, 16, 64);
    assert(reads == PREVIEW_IOV_MAX);
    reads = 0;
    preview_iov(out, sizeof(out), (unsigned long)input.vec, ~0UL, 64);
    assert(reads == 0 && strstr(out, "iov_unavailable"));
    input.vec[0] = (struct svc_iovec){1, 64};
    preview_iov(out, sizeof(out), (unsigned long)input.vec, 1, 64);
    assert(strstr(out, "unavailable_tail"));
    input.msg.iov = (unsigned long)input.vec;
    input.msg.iovlen = 1;
    input.msg.name = (unsigned long)input.data;
    input.msg.namelen = 128;
    input.msg.controllen = 24;
    preview_msg(out, sizeof(out), (unsigned long)&input.msg, 0, 1, 2);
    assert(strstr(out, "address_bytes=2"));
    assert(strstr(out, "control_not_decoded"));
    assert(!strstr(out, "hex="));
    preview_msg(out, sizeof(out), 0, 128, 0, 0);
    assert(strstr(out, "msg_unavailable"));
    char guard[64];
    memset(guard, 'Z', sizeof(guard));
    assert(preview_iov(guard + 1, 62, (unsigned long)input.vec, 1, 64) == 0);
    assert(guard[0] == 'Z' && guard[63] == 'Z');
    puts("bounded I/O preview checks passed");
    return 0;
}
