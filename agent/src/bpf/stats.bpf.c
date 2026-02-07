// SPDX-License-Identifier: GPL-2.0
/*
 * LumaShield Statistics Collection BPF Program
 * 
 * This program collects detailed network statistics that can be
 * read by the userspace agent.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Per-IP statistics
 */
struct ip_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
};

/**
 * Per-port statistics
 */
struct port_stats {
    __u64 connections;
    __u64 packets;
    __u64 bytes;
};

/**
 * Connection tracking entry
 */
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

struct conn_value {
    __u64 packets;
    __u64 bytes;
    __u64 start_time;
    __u64 last_seen;
    __u8 state;
    __u8 pad[7];
};

/* ============================================================================
 * BPF Maps
 * ============================================================================ */

/**
 * Top talkers - tracks most active source IPs
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct ip_stats);
} top_talkers SEC(".maps");

/**
 * Port statistics
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, struct port_stats);
} port_stats SEC(".maps");

/**
 * Connection tracking
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct conn_key);
    __type(value, struct conn_value);
} connections SEC(".maps");

/**
 * Protocol counters
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);  /* One entry per protocol number */
    __type(key, __u32);
    __type(value, __u64);
} protocol_counters SEC(".maps");

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static __always_inline void update_top_talkers(__u32 ip, __u32 bytes) {
    struct ip_stats *stats = bpf_map_lookup_elem(&top_talkers, &ip);
    
    if (stats) {
        stats->packets++;
        stats->bytes += bytes;
        stats->last_seen = bpf_ktime_get_ns();
    } else {
        struct ip_stats new_stats = {
            .packets = 1,
            .bytes = bytes,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&top_talkers, &ip, &new_stats, BPF_ANY);
    }
}

static __always_inline void update_port_stats(__u16 port, __u32 bytes) {
    struct port_stats *stats = bpf_map_lookup_elem(&port_stats, &port);
    
    if (stats) {
        stats->packets++;
        stats->bytes += bytes;
    } else {
        struct port_stats new_stats = {
            .connections = 1,
            .packets = 1,
            .bytes = bytes,
        };
        bpf_map_update_elem(&port_stats, &port, &new_stats, BPF_ANY);
    }
}

static __always_inline void track_connection(struct conn_key *key, __u32 bytes) {
    struct conn_value *conn = bpf_map_lookup_elem(&connections, key);
    
    if (conn) {
        conn->packets++;
        conn->bytes += bytes;
        conn->last_seen = bpf_ktime_get_ns();
    } else {
        struct conn_value new_conn = {
            .packets = 1,
            .bytes = bytes,
            .start_time = bpf_ktime_get_ns(),
            .last_seen = bpf_ktime_get_ns(),
            .state = 1,  /* Active */
        };
        bpf_map_update_elem(&connections, key, &new_conn, BPF_ANY);
    }
}

/* ============================================================================
 * XDP Program
 * ============================================================================ */

SEC("xdp")
int xdp_stats_collector(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    __u32 packet_size = data_end - data;
    
    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    /* Update protocol counter */
    __u32 proto_key = ip->protocol;
    __u64 *proto_count = bpf_map_lookup_elem(&protocol_counters, &proto_key);
    if (proto_count)
        (*proto_count)++;
    
    /* Update top talkers */
    update_top_talkers(ip->saddr, packet_size);
    
    /* Parse transport layer for port stats and connection tracking */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        /* Update destination port stats */
        update_port_stats(bpf_ntohs(tcp->dest), packet_size);
        
        /* Track connection */
        struct conn_key key = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
            .protocol = IPPROTO_TCP,
        };
        track_connection(&key, packet_size);
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        /* Update destination port stats */
        update_port_stats(bpf_ntohs(udp->dest), packet_size);
        
        /* Track connection */
        struct conn_key key = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = udp->source,
            .dst_port = udp->dest,
            .protocol = IPPROTO_UDP,
        };
        track_connection(&key, packet_size);
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
