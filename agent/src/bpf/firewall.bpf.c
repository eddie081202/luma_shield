// SPDX-License-Identifier: GPL-2.0
/*
 * LumaShield XDP Firewall
 * 
 * This eBPF program runs at the XDP hook point, processing packets
 * as soon as they arrive at the network interface - before the kernel
 * networking stack processes them.
 * 
 * Features:
 * - IP blacklist with O(1) lookup using BPF hash maps
 * - Per-IP packet counters
 * - Statistics collection
 * - Rate limiting (TODO)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define MAX_BLACKLIST_ENTRIES 100000
#define MAX_STATS_ENTRIES 256

/* XDP actions */
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Blacklist entry value
 * Stored in the blacklist map, keyed by IP address
 */
struct blacklist_value {
    __u64 drop_count;      /* Number of packets dropped from this IP */
    __u64 first_seen;      /* Timestamp when first blocked */
    __u64 last_seen;       /* Timestamp of last blocked packet */
    __u32 reason;          /* Reason code for blocking */
};

/**
 * Global statistics
 */
struct stats_value {
    __u64 packets_received;
    __u64 packets_passed;
    __u64 packets_dropped;
    __u64 bytes_received;
    __u64 bytes_dropped;
    __u64 tcp_packets;
    __u64 udp_packets;
    __u64 icmp_packets;
    __u64 other_packets;
};

/* ============================================================================
 * BPF Maps
 * ============================================================================ */

/**
 * Blacklist map
 * Key: IPv4 address (__u32 in network byte order)
 * Value: blacklist_value struct
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
    __type(key, __u32);
    __type(value, struct blacklist_value);
} blacklist SEC(".maps");

/**
 * Statistics map
 * Key: CPU ID (for per-CPU stats) or 0 for global
 * Value: stats_value struct
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_value);
} stats SEC(".maps");

/**
 * Configuration map
 * Key: config key (0 = enabled, 1 = mode, etc.)
 * Value: config value
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} config SEC(".maps");

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * Parse Ethernet header and return pointer to next header
 */
static __always_inline struct iphdr *parse_ethhdr(void *data, void *data_end) {
    struct ethhdr *eth = data;
    
    /* Bounds check */
    if ((void *)(eth + 1) > data_end)
        return NULL;
    
    /* Only handle IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return NULL;
    
    struct iphdr *ip = (void *)(eth + 1);
    
    /* Bounds check for IP header */
    if ((void *)(ip + 1) > data_end)
        return NULL;
    
    return ip;
}

/**
 * Update statistics
 */
static __always_inline void update_stats(struct stats_value *stats, 
                                         __u32 bytes, 
                                         __u8 protocol,
                                         int dropped) {
    if (!stats)
        return;
    
    stats->packets_received++;
    stats->bytes_received += bytes;
    
    if (dropped) {
        stats->packets_dropped++;
        stats->bytes_dropped += bytes;
    } else {
        stats->packets_passed++;
    }
    
    /* Count by protocol */
    switch (protocol) {
        case IPPROTO_TCP:
            stats->tcp_packets++;
            break;
        case IPPROTO_UDP:
            stats->udp_packets++;
            break;
        case IPPROTO_ICMP:
            stats->icmp_packets++;
            break;
        default:
            stats->other_packets++;
            break;
    }
}

/* ============================================================================
 * XDP Program
 * ============================================================================ */

/**
 * Main XDP firewall program
 * 
 * This is the entry point for all incoming packets.
 * It runs at the earliest possible point in the network stack.
 */
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    /* Get packet data pointers */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* Calculate packet size */
    __u32 packet_size = data_end - data;
    
    /* Get stats entry */
    __u32 stats_key = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&stats, &stats_key);
    
    /* Parse Ethernet and IP headers */
    struct iphdr *ip = parse_ethhdr(data, data_end);
    if (!ip) {
        /* Not IPv4 - let it pass */
        return XDP_PASS;
    }
    
    /* Get source IP address */
    __u32 src_ip = ip->saddr;
    
    /* Check blacklist */
    struct blacklist_value *blocked = bpf_map_lookup_elem(&blacklist, &src_ip);
    
    if (blocked) {
        /* IP is blacklisted - DROP the packet */
        
        /* Update blacklist entry statistics */
        blocked->drop_count++;
        blocked->last_seen = bpf_ktime_get_ns();
        
        /* Update global stats */
        update_stats(stats, packet_size, ip->protocol, 1);
        
        /* Log (can be read via trace_pipe) */
        bpf_printk("BLOCKED: src=%pI4 proto=%d size=%d", 
                   &src_ip, ip->protocol, packet_size);
        
        /* DROP - packet is discarded at NIC level */
        return XDP_DROP;
    }
    
    /* IP not blacklisted - update stats and PASS */
    update_stats(stats, packet_size, ip->protocol, 0);
    
    return XDP_PASS;
}

/**
 * XDP program for rate limiting (optional)
 * Uses a sliding window counter per IP
 */
SEC("xdp")
int xdp_ratelimit(struct xdp_md *ctx) {
    /* TODO: Implement rate limiting */
    return XDP_PASS;
}

/* License declaration (required for some BPF helpers) */
char LICENSE[] SEC("license") = "GPL";
