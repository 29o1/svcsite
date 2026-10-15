/* Controlled ARM64 registration evidence: only PID-specific temporary files
 * and a read-only Binder version query. Does not register with any service. */
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static int checks, failures;
#define CHECK(expr) do { checks++; if (!(expr)) { failures++; fprintf(stderr, "line %d failed: %s errno=%d\n", __LINE__, #expr, errno); } } while (0)
static unsigned long long ns(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock, &value)) abort();
    return (unsigned long long)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

int main(int argc, char **argv) {
    char path[128], renamed[140], final[140], missing[140], fd_path[64], link[256];
    char bytes[4096] = "registration-fixture";
    snprintf(path, sizeof(path), "/data/local/tmp/svcsite-registration-%d", getpid());
    snprintf(renamed, sizeof(renamed), "%s.renamed", path);
    snprintf(final, sizeof(final), "%s.final", path);
    snprintf(missing, sizeof(missing), "%s.absent", path);
    sleep(argc > 1 ? (unsigned int)atoi(argv[1]) : 5);
    unsigned long long begin = ns(CLOCK_MONOTONIC);
    int fd = syscall(__NR_openat, AT_FDCWD, path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    if (fd < 0) return 1;
    CHECK(syscall(__NR_write, fd, bytes, sizeof(bytes)) == sizeof(bytes));
    struct stat st;
    CHECK(syscall(__NR_fstat, fd, &st) == 0 && st.st_size == sizeof(bytes));
    CHECK(syscall(__NR_newfstatat, AT_FDCWD, path, &st, 0) == 0);
    CHECK(syscall(__NR_faccessat, AT_FDCWD, path, F_OK) == 0);
    CHECK(syscall(__NR_fcntl, fd, F_GETFL, 0) >= 0);
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    long link_len = syscall(__NR_readlinkat, AT_FDCWD, fd_path, link, sizeof(link) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) { link[link_len] = 0; CHECK(strcmp(path, link) == 0); }
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    struct iovec io[2] = {{bytes, 8}, {bytes + 8, 8}};
    CHECK(syscall(__NR_readv, fd, io, 2) == 16);
    CHECK(syscall(__NR_writev, fd, io, 2) == 16);
    unsigned long long mmap_before = ns(CLOCK_MONOTONIC);
    void *mapped = (void *)syscall(__NR_mmap, 0, sizeof(bytes), PROT_READ, MAP_SHARED, fd, 0);
    unsigned long long mmap_after = ns(CLOCK_MONOTONIC);
    CHECK(mapped != MAP_FAILED);
    if (mapped != MAP_FAILED) {
        CHECK(memcmp(mapped, "registration", 12) == 0);
        CHECK(munmap(mapped, sizeof(bytes)) == 0);
    }
    void *anonymous = (void *)syscall(__NR_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, fd, 0);
    CHECK(anonymous != MAP_FAILED);
    if (anonymous != MAP_FAILED) CHECK(munmap(anonymous, 4096) == 0);
    CHECK(syscall(__NR_mmap, 0, 4096, PROT_READ, MAP_SHARED, -1, 0) == -1 && errno == EBADF);
    CHECK(syscall(__NR_ioctl, fd, 0x12345678, bytes) == -1);
    int file_ioctl_errno = errno;
    /* SELinux can reject this request before the filesystem ioctl handler. */
    CHECK(file_ioctl_errno == ENOTTY || file_ioctl_errno == EACCES);
    CHECK(syscall(__NR_ioctl, -1, FIONREAD, bytes) == -1 && errno == EBADF);
    int binder = syscall(__NR_openat, AT_FDCWD, "/dev/binder", O_RDONLY | O_CLOEXEC, 0);
    CHECK(binder >= 0);
    struct binder_version version = {0};
    if (binder >= 0) {
        CHECK(syscall(__NR_ioctl, binder, BINDER_VERSION, &version) == 0);
        CHECK(version.protocol_version > 0);
        CHECK(syscall(__NR_close, binder) == 0);
    }
    CHECK(syscall(__NR_renameat, AT_FDCWD, path, AT_FDCWD, renamed) == 0);
    CHECK(syscall(__NR_renameat, AT_FDCWD, missing, AT_FDCWD, path) == -1 && errno == ENOENT);
    CHECK(syscall(__NR_renameat2, AT_FDCWD, renamed, AT_FDCWD, final, 0) == 0);
    CHECK(syscall(__NR_renameat2, AT_FDCWD, missing, AT_FDCWD, path, 0) == -1 && errno == ENOENT);
    CHECK(syscall(__NR_pread64, fd, bytes, 8, 0) == 8);
    CHECK(syscall(__NR_pwrite64, fd, "saved", 5, 0) == 5);
    CHECK(syscall(__NR_unlinkat, AT_FDCWD, missing, 0) == -1 && errno == ENOENT);
    CHECK(syscall(__NR_unlinkat, AT_FDCWD, final, 0) == 0);
    CHECK(syscall(__NR_close, fd) == 0);
    unsigned long long mono_before = ns(CLOCK_MONOTONIC);
    unsigned long long realtime = ns(CLOCK_REALTIME);
    unsigned long long mono_after = ns(CLOCK_MONOTONIC);
    printf("{\"checks\":%d,\"failures\":%d,\"pid\":%d,\"fd\":%d,\"binder_fd\":%d,\"file_ioctl_errno\":%d,"
           "\"path\":\"%s\",\"begin_ns\":%llu,\"mmap_before_ns\":%llu,\"mmap_after_ns\":%llu,"
           "\"mapped_address\":%llu,\"monotonic_before_ns\":%llu,\"realtime_ns\":%llu,\"monotonic_after_ns\":%llu}\n",
           checks, failures, getpid(), fd, binder, file_ioctl_errno, path, begin, mmap_before, mmap_after,
           (unsigned long long)mapped, mono_before, realtime, mono_after);
    fflush(stdout);
    /* Keep /proc/PID/maps available until capture completes. */
    sleep(10);
    return failures ? 1 : 0;
}
