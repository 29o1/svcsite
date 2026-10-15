/* Compact, lossless hex plus searchable ASCII; no repeated rows or strings. */
static int data_preview(char *buf, int blen, unsigned long uptr, unsigned long datalen)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char bytes[DATA_PREVIEW];
    int i, got, n, wanted;
    if (blen < 80) return 0;
    wanted = datalen < DATA_PREVIEW ? (int)datalen : DATA_PREVIEW;
    /* Each byte needs two hex digits and at most two escaped ASCII bytes. */
    if (wanted > (blen - 80) / 4) wanted = (blen - 80) / 4;
    if (!is_user_addr(uptr) || wanted <= 0)
        return snprintf(buf, blen, "buf=0x%lx", uptr);
    got = safe_copy_user_bytes((char *)bytes, uptr, wanted);
    if (got <= 0)
        return snprintf(buf, blen, "buf=0x%lx", uptr);
    n = snprintf(buf, blen, "data[%d/%lu] hex=", got, datalen);
    for (i = 0; i < got; i++) {
        buf[n++] = hex[bytes[i] >> 4];
        buf[n++] = hex[bytes[i] & 15];
    }
    n += snprintf(buf + n, blen - n, " ascii=\"");
    for (i = 0; i < got; i++) {
        unsigned char c = bytes[i];
        if (c == '\\' || c == '\"') buf[n++] = '\\';
        buf[n++] = c >= 0x20 && c < 0x7f ? (char)c : '.';
    }
    buf[n++] = '\"';
    buf[n] = '\0';
    return n;
}

/* Android ARM64 user ABI. All nested reads are bounded, including zero-length iovecs. */
#define PREVIEW_IOV_MAX 8
struct svc_iovec {
    unsigned long base;
    unsigned long len;
};
struct svc_msghdr {
    unsigned long name;
    unsigned int namelen;
    unsigned int pad1;
    unsigned long iov;
    unsigned long iovlen;
    unsigned long control;
    unsigned long controllen;
    unsigned int flags;
    unsigned int pad2;
};
_Static_assert(sizeof(struct svc_iovec) == 16, "ARM64 iovec ABI");
_Static_assert(sizeof(struct svc_msghdr) == 56, "ARM64 msghdr ABI");

static int preview_iov(char *buf, int blen, unsigned long address,
                       unsigned long count, unsigned long available)
{
    unsigned char bytes[DATA_PREVIEW];
    unsigned long i, wanted = available < DATA_PREVIEW ? available : DATA_PREVIEW;
    unsigned int used = 0;
    int n = 0, incomplete = 0;
    if (blen < 128) return 0;
    if (count > 1024 || !is_user_addr(address))
        return snprintf(buf, blen, " iov_unavailable");
    for (i = 0; i < count && i < PREVIEW_IOV_MAX && used < wanted; i++) {
        struct svc_iovec v;
        unsigned long take;
        int got;
        if (safe_copy_user_bytes((char *)&v, address + i * sizeof(v), sizeof(v)) != sizeof(v)) {
            incomplete = 1;
            break;
        }
        take = v.len < wanted - used ? v.len : wanted - used;
        if (!take) continue;
        got = safe_copy_user_bytes((char *)bytes + used, v.base, (int)take);
        if (got > 0) used += got;
        if (got != (int)take) {
            incomplete = 1;
            break;
        }
    }
    n = snprintf(buf, blen, " preview_bytes=%u preview_limit=%d iov_limit=%d%s hex=",
                 used, DATA_PREVIEW, PREVIEW_IOV_MAX,
                 incomplete ? " unavailable_tail" : "");
    for (i = 0; i < used && n < blen - 3; i++)
        n += snprintf(buf + n, blen - n, "%02x", bytes[i]);
    return n;
}

static int preview_msg(char *buf, int blen, unsigned long address,
                       unsigned long available, int receiving, unsigned int name_capacity)
{
    struct svc_msghdr msg;
    int n = 0;
    if (blen < 192) return 0;
    if (safe_copy_user_bytes((char *)&msg, address, sizeof(msg)) != sizeof(msg))
        return snprintf(buf, blen, " msg_unavailable");
    n = snprintf(buf, blen, " msg_flags=0x%x", msg.flags);
    if (receiving && msg.namelen > name_capacity) msg.namelen = name_capacity;
    if (msg.name && msg.namelen) {
        n += snprintf(buf + n, blen - n, " peer=");
        n += parse_sockaddr(buf + n, blen - n, msg.name, (int)msg.namelen);
    }
    if (msg.controllen)
        n += snprintf(buf + n, blen - n, " control_bytes=%lu control_not_decoded", msg.controllen);
    if (!receiving || available > 0)
        n += preview_iov(buf + n, blen - n, msg.iov, msg.iovlen, available);
    return n;
}
