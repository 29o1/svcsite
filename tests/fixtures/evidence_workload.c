/* Android ARM64 regression workload; all network traffic stays on loopback.
 * Build with the NDK, run as shell, then capture this exact PID during the delay.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static int checks, failures;
#define CHECK(expr) do { checks++; if (!(expr)) { failures++; fprintf(stderr, "line %d failed: %s errno=%d\n", __LINE__, #expr, errno); } } while (0)

static int blocked_read(void) {
    int descriptors[2];
    char buffer[7] = {0};
    CHECK(pipe(descriptors) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        sleep(8);
        write(descriptors[1], "b", 1);
        _exit(0);
    }
    CHECK(syscall(__NR_read, descriptors[0], buffer, sizeof(buffer)) == 1);
    CHECK(buffer[0] == 'b');
    close(descriptors[0]);
    close(descriptors[1]);
    int fd = open("/proc/self/status", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(syscall(__NR_read, fd, buffer, 1) == 1);
    close(fd);
    printf("{\"checks\":%d,\"failures\":%d}\n", checks, failures);
    return failures ? 1 : 0;
}

int main(int argc, char **argv) {
    char path[128], missing[160], buffer[32] = {0};
    snprintf(path, sizeof(path), "/data/local/tmp/svcsite-evidence-%d.dat", getpid());
    snprintf(missing, sizeof(missing), "%s.absent", path);
    sleep(argc > 1 ? (unsigned int)atoi(argv[1]) : 10);
    if (argc > 2 && strcmp(argv[2], "blocked") == 0) return blocked_read();
    int fd = syscall(__NR_openat, AT_FDCWD, path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    if (fd < 0) return 1;
    struct iovec outgoing[2] = {{"ab", 2}, {"cdef", 4}};
    struct iovec incoming[2] = {{buffer, 2}, {buffer + 2, 16}};
    CHECK(syscall(__NR_writev, fd, outgoing, 2) == 6);
    CHECK(syscall(__NR_pread64, fd, buffer, 3, 0) == 3);
    CHECK(memcmp(buffer, "abc", 3) == 0);
    CHECK(syscall(__NR_pwrite64, fd, "XYZ", 3, 1) == 3);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(syscall(__NR_readv, fd, incoming, 2) == 6);
    CHECK(memcmp(buffer, "aXYZef", 6) == 0);
    CHECK(syscall(__NR_read, fd, buffer, 8) == 0);
    CHECK(syscall(__NR_read, -1, buffer, 8) == -1 && errno == EBADF);
    CHECK(syscall(__NR_writev, fd, (void *)1, 2) == -1 && errno == EFAULT);
    CHECK(syscall(__NR_openat, AT_FDCWD, missing, O_RDONLY, 0) == -1 && errno == ENOENT);
    CHECK(syscall(__NR_prctl, PR_GET_DUMPABLE, 0, 0, 0, 0) >= 0);
    CHECK(syscall(__NR_ptrace, -1, 0, 0, 0) == -1);
    CHECK(syscall(__NR_close, fd) == 0);
    int reused = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0);
    CHECK(reused == fd);
    CHECK(syscall(__NR_read, reused, buffer, 1) == 1);
    CHECK(syscall(__NR_close, reused) == 0);

    int server = syscall(__NR_socket, AF_INET, SOCK_DGRAM, 0);
    int client = syscall(__NR_socket, AF_INET, SOCK_DGRAM, 0);
    CHECK(server >= 0 && client >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t address_len = sizeof(address);
    CHECK(bind(server, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(getsockname(server, (struct sockaddr *)&address, &address_len) == 0);
    CHECK(syscall(__NR_connect, client, &address, sizeof(address)) == 0);
    int error = -1;
    socklen_t error_len = sizeof(error);
    CHECK(syscall(__NR_getsockopt, client, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 && error == 0);
    CHECK(syscall(__NR_sendto, client, "hi", 2, 0, 0, 0) == 2);
    struct sockaddr_in peer = {0};
    socklen_t peer_len = sizeof(peer);
    CHECK(syscall(__NR_recvfrom, server, buffer, sizeof(buffer), 0, &peer, &peer_len) == 2);
    CHECK(memcmp(buffer, "hi", 2) == 0);
    struct msghdr send_header = {.msg_iov = outgoing, .msg_iovlen = 2};
    struct msghdr recv_header = {.msg_name = &peer, .msg_namelen = sizeof(peer),
                                 .msg_iov = incoming, .msg_iovlen = 2};
    CHECK(syscall(__NR_sendmsg, client, &send_header, 0) == 6);
    CHECK(syscall(__NR_recvmsg, server, &recv_header, 0) == 6);
    CHECK(memcmp(buffer, "abcdef", 6) == 0);
    incoming[0].iov_len = 1;
    incoming[1].iov_len = 2;
    CHECK(syscall(__NR_sendmsg, client, &send_header, 0) == 6);
    CHECK(syscall(__NR_recvmsg, server, &recv_header, MSG_TRUNC) == 6);
    CHECK((recv_header.msg_flags & MSG_TRUNC) != 0);
    CHECK(syscall(__NR_recvfrom, -1, buffer, sizeof(buffer), 0, 0, 0) == -1 && errno == EBADF);
    CHECK(syscall(__NR_sendmsg, client, (void *)1, 0) == -1 && errno == EFAULT);
    CHECK(syscall(__NR_close, client) == 0);
    CHECK(syscall(__NR_close, server) == 0);

    server = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_port = 0;
    CHECK(bind(server, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(getsockname(server, (struct sockaddr *)&address, &address_len) == 0);
    client = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(syscall(__NR_connect, client, &address, sizeof(address)) == -1 && errno == EINPROGRESS);
    usleep(100000);
    error_len = sizeof(error);
    CHECK(syscall(__NR_getsockopt, client, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0);
    CHECK(error == ECONNREFUSED);
    close(client);
    close(server);
    unlink(path);
    printf("{\"checks\":%d,\"failures\":%d}\n", checks, failures);
    return failures ? 1 : 0;
}
