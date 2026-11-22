#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

#define CAS_XDP_ACTION_DROP 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} deny_src_ipv4 SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;

SEC("xdp")
int cas_xdp_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *ethernet = data;
    struct iphdr *ipv4;
    __u32 header_length;
    __u8 *action;

    if ((void *)(ethernet + 1) > data_end)
        return XDP_PASS;

    /* Non-IPv4 traffic, including VLAN-tagged and IPv6 frames, passes through. */
    if (ethernet->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    ipv4 = (void *)(ethernet + 1);
    if ((void *)(ipv4 + 1) > data_end)
        return XDP_PASS;

    if (ipv4->version != 4 || ipv4->ihl < 5)
        return XDP_PASS;

    header_length = (__u32)ipv4->ihl * 4;
    if ((void *)((char *)ipv4 + header_length) > data_end)
        return XDP_PASS;

    /* The map key is the four source-address bytes in network byte order. */
    action = bpf_map_lookup_elem(&deny_src_ipv4, &ipv4->saddr);
    if (action && *action == CAS_XDP_ACTION_DROP)
        return XDP_DROP;

    /* XDP_PASS is normal-stack pass-through, not fail-closed behavior. */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
