// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// probes.bpf.c - eBPF syscall monitoring probes
// Compile with: clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I vmlinux.h -c probes.bpf.c -o probes.bpf.o
// Or use bpf2go via go generate.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN   16
#define SYSCALL_NAME_LEN 32
#define CONTAINER_ID_LEN 64
#define CGROUP_PATH_LEN  256
#define MAX_ARGS         6
#define MAX_STRING_LEN   256

// Syscall IDs (x86_64) - used for tagging
#define SYS_EXECVE      59
#define SYS_EXECVEAT    322
#define SYS_OPEN        2
#define SYS_OPENAT      257
#define SYS_OPENAT2     437
#define SYS_CREAT       85
#define SYS_WRITE       1
#define SYS_WRITEV      20
#define SYS_PWRITE64    18
#define SYS_PWRITEV     296
#define SYS_CHMOD       90
#define SYS_FCHMOD      91
#define SYS_FCHMODAT    268
#define SYS_CHOWN       92
#define SYS_FCHOWN      93
#define SYS_LCHOWN      94
#define SYS_FCHOWNAT    260
#define SYS_SOCKET      41
#define SYS_CONNECT     42
#define SYS_BIND        49
#define SYS_LISTEN      50
#define SYS_ACCEPT      43
#define SYS_ACCEPT4     288
#define SYS_CLONE       56
#define SYS_FORK        57
#define SYS_VFORK       58
#define SYS_CLONE3      435
#define SYS_SETUID      105
#define SYS_SETGID      106
#define SYS_SETREUID    113
#define SYS_SETREGID    114
#define SYS_SETRESUID   117
#define SYS_SETRESGID   119
#define SYS_CAPSET      126

// ─── Event Structure ──────────────────────────────────────────────────────────

struct syscall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u32 syscall_id;
    char  comm[TASK_COMM_LEN];
    char  syscall_name[SYSCALL_NAME_LEN];
    __u64 args[MAX_ARGS];
    __s64 ret;
    char  container_id[CONTAINER_ID_LEN];
    // Inline string data (for path, filename, etc.)
    char  str_arg0[MAX_STRING_LEN];
    char  str_arg1[MAX_STRING_LEN];
};

// ─── BPF Maps ─────────────────────────────────────────────────────────────────

// Ring buffer for event delivery to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16 MB ring buffer
} events SEC(".maps");

// Hash map: PID → entry-time args (for correlating entry↔exit)
struct entry_args {
    __u64 args[MAX_ARGS];
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // (pid<<32)|tid
    __type(value, struct entry_args);
} entry_map SEC(".maps");

// Container filter map: allow userspace to configure cgroup prefixes to watch.
// Key = 0 means "monitor all containers", key = 1 means "use filter list".
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // 0 = all, 1 = filter
} config_map SEC(".maps");

// Sampling counter for high-frequency syscalls (write, writev, etc.)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 512); // indexed by syscall_id
    __type(key, __u32);
    __type(value, __u64);
} sample_counters SEC(".maps");

// ─── Helper Functions ─────────────────────────────────────────────────────────

// Returns non-zero if the current task is inside a Docker/k8s cgroup.
// We check the cgroup name via bpf_get_current_cgroup_id(). For a richer
// check the userspace side reads /proc/<pid>/cgroup and parses Docker IDs.
static __always_inline int is_container_process(void)
{
    // A cgroup ID of 1 is typically the root cgroup (host).
    // Container processes live in deeper cgroups (ID > 1).
    // This is a best-effort filter; the Go side refines it.
    __u64 cgid = bpf_get_current_cgroup_id();
    return (cgid > 1) ? 1 : 0;
}

// Sampling: returns 1 if this event should be emitted, 0 if it should be dropped.
// High-frequency syscalls are sampled at 1-in-N to cap overhead.
static __always_inline int should_sample(__u32 syscall_id, __u32 rate)
{
    if (rate <= 1)
        return 1;

    __u64 *cnt = bpf_map_lookup_elem(&sample_counters, &syscall_id);
    if (!cnt)
        return 1;

    __u64 val = __sync_fetch_and_add(cnt, 1);
    return (val % rate == 0) ? 1 : 0;
}

// Copy the cgroup path into container_id field (truncated).
// Full Docker ID extraction happens in userspace.
static __always_inline void fill_container_id(char *out, int len)
{
    // Zero out the buffer
    __builtin_memset(out, 0, len);
    // We embed cgroup_id as a hex hint; Go side does the real lookup.
    __u64 cgid = bpf_get_current_cgroup_id();
    // Store numeric cgroup ID as decimal string prefix; Go replaces this.
    // (bpf_snprintf is available on 5.13+; for older kernels store raw u64)
    __u64 *ptr = (__u64 *)out;
    if (len >= (int)sizeof(__u64))
        *ptr = cgid;
}

// Reserve a ring buffer slot, populate common fields, return pointer or NULL.
static __always_inline struct syscall_event *
new_event(__u32 syscall_id, const char *name, int name_len)
{
    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;

    __u64 id      = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid(); /* u64: uid=low32, gid=high32 */

    e->timestamp  = bpf_ktime_get_ns();
    e->pid        = (__u32)(id >> 32);
    e->tid        = (__u32)id;
    e->uid        = (__u32)uid_gid;           /* low  32 bits = UID */
    e->gid        = (__u32)(uid_gid >> 32);   /* high 32 bits = GID */
    e->syscall_id = syscall_id;
    e->ret        = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->syscall_name, 0, sizeof(e->syscall_name));
    // Safe bounded copy
    if (name_len > (int)sizeof(e->syscall_name) - 1)
        name_len = sizeof(e->syscall_name) - 1;
    bpf_probe_read_kernel(e->syscall_name, name_len, name);

    fill_container_id(e->container_id, sizeof(e->container_id));

    return e;
}

// ─── Tracepoint: sys_enter_execve ─────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "execve";
    struct syscall_event *e = new_event(SYS_EXECVE, name, sizeof(name) - 1);
    if (!e)
        return 0;

    // arg[0] = const char *filename
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), filename);

    // arg[1] = const char *const *argv  (we capture argv[0])
    const char *const *argv = (const char *const *)ctx->args[1];
    const char *argv0 = NULL;
    bpf_probe_read_user(&argv0, sizeof(argv0), &argv[0]);
    if (argv0)
        bpf_probe_read_user_str(e->str_arg1, sizeof(e->str_arg1), argv0);

    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2]; // envp

    // Save entry state for exit correlation
    __u64 key = (((__u64)e->pid) << 32) | e->tid;
    struct entry_args ea = {};
    ea.timestamp = e->timestamp;
    ea.args[0] = ctx->args[0];
    bpf_map_update_elem(&entry_map, &key, &ea, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id  = bpf_get_current_pid_tgid();
    __u64 key = id; // (pid<<32)|tid

    struct entry_args *ea = bpf_map_lookup_elem(&entry_map, &key);
    if (!ea)
        return 0;

    const char name[] = "execve_ret";
    struct syscall_event *e = new_event(SYS_EXECVE, name, sizeof(name) - 1);
    if (!e) {
        bpf_map_delete_elem(&entry_map, &key);
        return 0;
    }

    e->ret    = ctx->ret;
    e->args[0] = ea->args[0];

    bpf_map_delete_elem(&entry_map, &key);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: sys_enter_execveat ───────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "execveat";
    struct syscall_event *e = new_event(SYS_EXECVEAT, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // dirfd
    e->args[1] = ctx->args[1]; // pathname
    e->args[2] = ctx->args[2]; // argv
    e->args[3] = ctx->args[3]; // envp
    e->args[4] = ctx->args[4]; // flags

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: open / openat / creat ────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "open";
    struct syscall_event *e = new_event(SYS_OPEN, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // pathname
    e->args[1] = ctx->args[1]; // flags
    e->args[2] = ctx->args[2]; // mode

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "openat";
    struct syscall_event *e = new_event(SYS_OPENAT, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // dirfd
    e->args[1] = ctx->args[1]; // pathname
    e->args[2] = ctx->args[2]; // flags
    e->args[3] = ctx->args[3]; // mode

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "creat";
    struct syscall_event *e = new_event(SYS_CREAT, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // pathname
    e->args[1] = ctx->args[1]; // mode

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: write / writev (sampled 1-in-100) ────────────────────────────

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;
    if (!should_sample(SYS_WRITE, 100))
        return 0;

    const char name[] = "write";
    struct syscall_event *e = new_event(SYS_WRITE, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // fd
    e->args[1] = ctx->args[1]; // buf
    e->args[2] = ctx->args[2]; // count

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;
    if (!should_sample(SYS_WRITEV, 100))
        return 0;

    const char name[] = "writev";
    struct syscall_event *e = new_event(SYS_WRITEV, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // fd
    e->args[1] = ctx->args[1]; // iov
    e->args[2] = ctx->args[2]; // iovcnt

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: chmod / fchmod / fchmodat ────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "chmod";
    struct syscall_event *e = new_event(SYS_CHMOD, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // pathname
    e->args[1] = ctx->args[1]; // mode

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_fchmod_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "fchmod";
    struct syscall_event *e = new_event(SYS_FCHMOD, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // fd
    e->args[1] = ctx->args[1]; // mode

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "fchmodat";
    struct syscall_event *e = new_event(SYS_FCHMODAT, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // dirfd
    e->args[1] = ctx->args[1]; // pathname
    e->args[2] = ctx->args[2]; // mode
    e->args[3] = ctx->args[3]; // flags

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: chown / fchown / lchown / fchownat ──────────────────────────

SEC("tracepoint/syscalls/sys_enter_chown")
int trace_chown_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "chown";
    struct syscall_event *e = new_event(SYS_CHOWN, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // pathname
    e->args[1] = ctx->args[1]; // owner
    e->args[2] = ctx->args[2]; // group

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int trace_fchown_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "fchown";
    struct syscall_event *e = new_event(SYS_FCHOWN, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // fd
    e->args[1] = ctx->args[1]; // owner
    e->args[2] = ctx->args[2]; // group

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int trace_lchown_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "lchown";
    struct syscall_event *e = new_event(SYS_LCHOWN, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // pathname
    e->args[1] = ctx->args[1]; // owner
    e->args[2] = ctx->args[2]; // group

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_fchownat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "fchownat";
    struct syscall_event *e = new_event(SYS_FCHOWNAT, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // dirfd
    e->args[1] = ctx->args[1]; // pathname
    e->args[2] = ctx->args[2]; // owner
    e->args[3] = ctx->args[3]; // group
    e->args[4] = ctx->args[4]; // flags

    bpf_probe_read_user_str(e->str_arg0, sizeof(e->str_arg0), (const char *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: socket / connect / bind / listen / accept ───────────────────

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "socket";
    struct syscall_event *e = new_event(SYS_SOCKET, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // domain (AF_INET, AF_UNIX, ...)
    e->args[1] = ctx->args[1]; // type   (SOCK_STREAM, ...)
    e->args[2] = ctx->args[2]; // protocol

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "connect";
    struct syscall_event *e = new_event(SYS_CONNECT, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // sockfd
    e->args[1] = ctx->args[1]; // addr
    e->args[2] = ctx->args[2]; // addrlen

    // Capture first 16 bytes of sockaddr for IP parsing in userspace
    bpf_probe_read_user(e->str_arg0, 16, (const void *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "bind";
    struct syscall_event *e = new_event(SYS_BIND, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // sockfd
    e->args[1] = ctx->args[1]; // addr
    e->args[2] = ctx->args[2]; // addrlen

    bpf_probe_read_user(e->str_arg0, 16, (const void *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "listen";
    struct syscall_event *e = new_event(SYS_LISTEN, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // sockfd
    e->args[1] = ctx->args[1]; // backlog

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "accept";
    struct syscall_event *e = new_event(SYS_ACCEPT, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // sockfd

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "accept4";
    struct syscall_event *e = new_event(SYS_ACCEPT4, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // sockfd
    e->args[3] = ctx->args[3]; // flags

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: clone / fork / vfork ────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "clone";
    struct syscall_event *e = new_event(SYS_CLONE, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // flags
    e->args[1] = ctx->args[1]; // newsp
    e->args[2] = ctx->args[2]; // parent_tidptr
    e->args[3] = ctx->args[3]; // child_tidptr
    e->args[4] = ctx->args[4]; // tls

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "fork";
    struct syscall_event *e = new_event(SYS_FORK, name, sizeof(name) - 1);
    if (!e)
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int trace_vfork_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "vfork";
    struct syscall_event *e = new_event(SYS_VFORK, name, sizeof(name) - 1);
    if (!e)
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: setuid / setgid / setreuid / setregid / setresuid / setresgid

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "setuid";
    struct syscall_event *e = new_event(SYS_SETUID, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // uid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "setgid";
    struct syscall_event *e = new_event(SYS_SETGID, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // gid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_setreuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "setreuid";
    struct syscall_event *e = new_event(SYS_SETREUID, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // ruid
    e->args[1] = ctx->args[1]; // euid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_setregid_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "setregid";
    struct syscall_event *e = new_event(SYS_SETREGID, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // rgid
    e->args[1] = ctx->args[1]; // egid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "setresuid";
    struct syscall_event *e = new_event(SYS_SETRESUID, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // ruid
    e->args[1] = ctx->args[1]; // euid
    e->args[2] = ctx->args[2]; // suid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "setresgid";
    struct syscall_event *e = new_event(SYS_SETRESGID, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // rgid
    e->args[1] = ctx->args[1]; // egid
    e->args[2] = ctx->args[2]; // sgid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── Tracepoint: capset ───────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_container_process())
        return 0;

    const char name[] = "capset";
    struct syscall_event *e = new_event(SYS_CAPSET, name, sizeof(name) - 1);
    if (!e)
        return 0;

    e->args[0] = ctx->args[0]; // header
    e->args[1] = ctx->args[1]; // data (capabilities)

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";