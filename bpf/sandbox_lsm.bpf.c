// SPDX-License-Identifier: Apache-2.0
// Least-Privilege Agent Sandbox Berkeley Packet Filter Linux Security Module prototype. Runtime loading requires a kernel booted with lsm=...,bpf.
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Apache-2.0";

struct policy_value {
    __u32 allow_files;
    __u32 allow_exec;
    __u32 allow_net;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct policy_value);
} sandbox_policy SEC(".maps");

static __always_inline struct policy_value *current_policy(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&sandbox_policy, &cg);
}

SEC("lsm/file_open")
int BPF_PROG(sandbox_file_open, struct file *file)
{
    struct policy_value *p = current_policy();
    if (!p || !p->allow_files)
        return -EACCES;
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(sandbox_bprm_check_security, struct linux_binprm *bprm)
{
    struct policy_value *p = current_policy();
    if (!p || !p->allow_exec)
        return -EACCES;
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(sandbox_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct policy_value *p = current_policy();
    if (!p || !p->allow_net)
        return -EACCES;
    return 0;
}
