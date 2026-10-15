/* Static ARM64 whitelist. Table entries live until the module is unloaded. */
static void after_generic_ret(hook_fargs0_t *args, void *udata);
static void after_clone_ret(hook_fargs0_t *args, void *udata);

typedef struct {
    int nr;
    int narg;
    void *after;
    int active;
    int method;
} hook_entry_t;

static hook_entry_t hooks[] = {
    { 56, 4, (void *)after_generic_ret, 0, 0 }, /* openat */
    { 57, 1, (void *)after_generic_ret, 0, 0 }, /* close */
    { 48, 4, 0, 0, 0 }, /* faccessat */
    { 35, 3, (void *)after_generic_ret, 0, 0 }, /* unlinkat */
    { 78, 4, 0, 0, 0 }, /* readlinkat */
    { 79, 4, 0, 0, 0 }, /* newfstatat */
    { 80, 2, 0, 0, 0 }, /* fstat */
    { 61, 3, 0, 0, 0 }, /* getdents64 */
    { 63, 3, (void *)after_generic_ret, 0, 0 }, /* read */
    { 64, 3, (void *)after_generic_ret, 0, 0 }, /* write */
    { 221, 3, 0, 0, 0 }, /* execve */
    { 220, 5, (void *)after_clone_ret, 0, 0 }, /* clone */
    { 435, 2, (void *)after_clone_ret, 0, 0 }, /* clone3 */
    { 93, 1, 0, 0, 0 }, /* exit */
    { 94, 1, 0, 0, 0 }, /* exit_group */
    { 222, 6, (void *)after_generic_ret, 0, 0 }, /* mmap */
    { 226, 3, 0, 0, 0 }, /* mprotect */
    { 215, 2, 0, 0, 0 }, /* munmap */
    { 214, 1, 0, 0, 0 }, /* brk */
    { 232, 3, 0, 0, 0 }, /* mincore */
    { 198, 3, (void *)after_generic_ret, 0, 0 }, /* socket */
    { 200, 3, 0, 0, 0 }, /* bind */
    { 203, 3, (void *)after_generic_ret, 0, 0 }, /* connect */
    { 206, 6, (void *)after_generic_ret, 0, 0 }, /* sendto */
    { 207, 6, (void *)after_generic_ret, 0, 0 }, /* recvfrom */
    { 117, 4, (void *)after_generic_ret, 0, 0 }, /* ptrace */
    { 167, 5, (void *)after_generic_ret, 0, 0 }, /* prctl */
    { 129, 2, 0, 0, 0 }, /* kill */
    { 131, 3, 0, 0, 0 }, /* tgkill */
    { 134, 4, 0, 0, 0 }, /* rt_sigaction */
    { 135, 4, 0, 0, 0 }, /* rt_sigprocmask */
    { 29, 3, (void *)after_generic_ret, 0, 0 }, /* ioctl */
    { 25, 3, (void *)after_generic_ret, 0, 0 }, /* fcntl */
    { 277, 3, 0, 0, 0 }, /* seccomp */
    { 280, 3, 0, 0, 0 }, /* bpf */
    { 279, 2, (void *)after_generic_ret, 0, 0 }, /* memfd_create */
    { 146, 1, 0, 0, 0 }, /* setuid */
    { 144, 1, 0, 0, 0 }, /* setgid */
    { 147, 3, 0, 0, 0 }, /* setresuid */
    { 105, 3, 0, 0, 0 }, /* init_module */
    { 273, 3, 0, 0, 0 }, /* finit_module */
    { 97, 1, 0, 0, 0 }, /* unshare */
    { 268, 2, 0, 0, 0 }, /* setns */
    { 261, 4, 0, 0, 0 }, /* prlimit64 */
    { 62, 3, 0, 0, 0 }, /* lseek */
    { 291, 5, 0, 0, 0 }, /* statx */
    { 65, 3, (void *)after_generic_ret, 0, 0 }, /* readv */
    { 66, 3, (void *)after_generic_ret, 0, 0 }, /* writev */
    { 67, 4, (void *)after_generic_ret, 0, 0 }, /* pread64 */
    { 68, 4, (void *)after_generic_ret, 0, 0 }, /* pwrite64 */
    { 209, 5, (void *)after_generic_ret, 0, 0 }, /* getsockopt */
    { 40, 5, 0, 0, 0 }, /* mount */
    { 39, 2, 0, 0, 0 }, /* umount2 */
    { 281, 5, 0, 0, 0 }, /* execveat */
    { 270, 5, 0, 0, 0 }, /* process_vm_readv */
    { 271, 5, 0, 0, 0 }, /* process_vm_writev */
    { 211, 3, (void *)after_generic_ret, 0, 0 }, /* sendmsg */
    { 212, 3, (void *)after_generic_ret, 0, 0 }, /* recvmsg */
    { 208, 5, 0, 0, 0 }, /* setsockopt */
    { 201, 2, 0, 0, 0 }, /* listen */
    { 202, 3, (void *)after_generic_ret, 0, 0 }, /* accept */
    { 242, 4, (void *)after_generic_ret, 0, 0 }, /* accept4 */
    { 210, 2, 0, 0, 0 }, /* shutdown */
    { 106, 2, 0, 0, 0 }, /* delete_module */
    { 34, 3, 0, 0, 0 }, /* mkdirat */
    { 38, 4, (void *)after_generic_ret, 0, 0 }, /* renameat */
    { 276, 5, (void *)after_generic_ret, 0, 0 }, /* renameat2 */
    { 53, 3, 0, 0, 0 }, /* fchmodat */
    { 54, 5, 0, 0, 0 }, /* fchownat */
    { 21, 4, 0, 0, 0 }, /* epoll_ctl */
    { 27, 3, 0, 0, 0 }, /* inotify_add_watch */
    { 5, 5, 0, 0, 0 }, /* setxattr */
    { 8, 4, 0, 0, 0 }, /* getxattr */
    { 233, 3, 0, 0, 0 }, /* madvise */
    { 98, 6, 0, 0, 0 }, /* futex */
};
#define HOOK_COUNT (sizeof(hooks) / sizeof(hooks[0]))
