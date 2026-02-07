/**
 * BPF Loader Implementation
 */

#include "bpf_loader.h"

#include <iostream>
#include <cstring>
#include <arpa/inet.h>

#ifdef __linux__
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#endif

namespace lumashield {

BPFLoader::BPFLoader(const std::string& bpf_object_path)
    : bpf_object_path_(bpf_object_path)
{
}

BPFLoader::~BPFLoader() {
    DetachAll();
    
#ifdef __linux__
    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
#endif
}

bool BPFLoader::Load() {
#ifdef __linux__
    // Set libbpf print callback for debugging
    libbpf_set_print([](enum libbpf_print_level level, const char *format, va_list args) -> int {
        if (level <= LIBBPF_INFO) {
            return vfprintf(stderr, format, args);
        }
        return 0;
    });
    
    // Open BPF object
    obj_ = bpf_object__open(bpf_object_path_.c_str());
    if (!obj_) {
        std::cerr << "[BPFLoader] Failed to open BPF object: " << bpf_object_path_ << std::endl;
        return false;
    }
    
    // Load BPF object into kernel
    int err = bpf_object__load(obj_);
    if (err) {
        std::cerr << "[BPFLoader] Failed to load BPF object: " << err << std::endl;
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }
    
    // Find maps
    blacklist_map_ = bpf_object__find_map_by_name(obj_, "blacklist");
    if (!blacklist_map_) {
        std::cerr << "[BPFLoader] Warning: blacklist map not found" << std::endl;
    }
    
    stats_map_ = bpf_object__find_map_by_name(obj_, "stats");
    if (!stats_map_) {
        std::cerr << "[BPFLoader] Warning: stats map not found" << std::endl;
    }
    
    loaded_ = true;
    std::cout << "[BPFLoader] BPF object loaded successfully" << std::endl;
    return true;
#else
    std::cerr << "[BPFLoader] BPF support requires Linux" << std::endl;
    return false;
#endif
}

bool BPFLoader::AttachXDP(const std::string& interface, const std::string& program_name) {
#ifdef __linux__
    if (!loaded_) {
        std::cerr << "[BPFLoader] BPF object not loaded" << std::endl;
        return false;
    }
    
    // Find the program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj_, program_name.c_str());
    if (!prog) {
        std::cerr << "[BPFLoader] Program not found: " << program_name << std::endl;
        return false;
    }
    
    // Get interface index
    int ifindex = GetInterfaceIndex(interface);
    if (ifindex < 0) {
        std::cerr << "[BPFLoader] Interface not found: " << interface << std::endl;
        return false;
    }
    
    // Attach XDP program
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        // Try with SKB mode (software mode, works without driver support)
        int prog_fd = bpf_program__fd(prog);
        int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            std::cerr << "[BPFLoader] Failed to attach XDP program: " << err << std::endl;
            return false;
        }
        std::cout << "[BPFLoader] Attached XDP in SKB mode to " << interface << std::endl;
    } else {
        attached_links_[interface] = link;
        std::cout << "[BPFLoader] Attached XDP in native mode to " << interface << std::endl;
    }
    
    return true;
#else
    return false;
#endif
}

void BPFLoader::DetachXDP(const std::string& interface) {
#ifdef __linux__
    auto it = attached_links_.find(interface);
    if (it != attached_links_.end()) {
        bpf_link__destroy(it->second);
        attached_links_.erase(it);
        std::cout << "[BPFLoader] Detached XDP from " << interface << std::endl;
    } else {
        // Try to detach by interface index
        int ifindex = GetInterfaceIndex(interface);
        if (ifindex >= 0) {
            bpf_xdp_detach(ifindex, 0, NULL);
        }
    }
#endif
}

void BPFLoader::DetachAll() {
#ifdef __linux__
    for (auto& [iface, link] : attached_links_) {
        if (link) {
            bpf_link__destroy(link);
        }
    }
    attached_links_.clear();
    std::cout << "[BPFLoader] Detached all XDP programs" << std::endl;
#endif
}

bool BPFLoader::AddToBlacklist(const std::string& ip) {
    uint32_t ip_addr = IpStringToUint32(ip);
    if (ip_addr == 0) {
        std::cerr << "[BPFLoader] Invalid IP address: " << ip << std::endl;
        return false;
    }
    return AddToBlacklist(ip_addr);
}

bool BPFLoader::AddToBlacklist(uint32_t ip) {
#ifdef __linux__
    if (!blacklist_map_) {
        std::cerr << "[BPFLoader] Blacklist map not available" << std::endl;
        return false;
    }
    
    // Convert to network byte order
    uint32_t key = htonl(ip);
    
    // Create value
    struct {
        uint64_t drop_count;
        uint64_t first_seen;
        uint64_t last_seen;
        uint32_t reason;
    } value = {0, 0, 0, 1};
    
    int map_fd = bpf_map__fd(blacklist_map_);
    int err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (err) {
        std::cerr << "[BPFLoader] Failed to add to blacklist: " << err << std::endl;
        return false;
    }
    
    return true;
#else
    return false;
#endif
}

bool BPFLoader::RemoveFromBlacklist(const std::string& ip) {
    uint32_t ip_addr = IpStringToUint32(ip);
    if (ip_addr == 0) {
        return false;
    }
    return RemoveFromBlacklist(ip_addr);
}

bool BPFLoader::RemoveFromBlacklist(uint32_t ip) {
#ifdef __linux__
    if (!blacklist_map_) {
        return false;
    }
    
    uint32_t key = htonl(ip);
    int map_fd = bpf_map__fd(blacklist_map_);
    int err = bpf_map_delete_elem(map_fd, &key);
    
    return err == 0;
#else
    return false;
#endif
}

bool BPFLoader::IsBlacklisted(const std::string& ip) const {
#ifdef __linux__
    if (!blacklist_map_) {
        return false;
    }
    
    uint32_t key = htonl(IpStringToUint32(ip));
    int map_fd = bpf_map__fd(blacklist_map_);
    
    struct {
        uint64_t drop_count;
        uint64_t first_seen;
        uint64_t last_seen;
        uint32_t reason;
    } value;
    
    return bpf_map_lookup_elem(map_fd, &key, &value) == 0;
#else
    return false;
#endif
}

std::vector<uint32_t> BPFLoader::GetBlacklist() const {
    std::vector<uint32_t> result;
    
#ifdef __linux__
    if (!blacklist_map_) {
        return result;
    }
    
    int map_fd = bpf_map__fd(blacklist_map_);
    uint32_t key = 0, next_key;
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        result.push_back(ntohl(next_key));
        key = next_key;
    }
#endif
    
    return result;
}

BPFStats BPFLoader::GetStats() const {
    BPFStats stats = {0};
    
#ifdef __linux__
    if (!stats_map_) {
        return stats;
    }
    
    int map_fd = bpf_map__fd(stats_map_);
    uint32_t key = 0;
    
    // For per-CPU maps, we need to aggregate across all CPUs
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        return stats;
    }
    
    struct {
        uint64_t packets_received;
        uint64_t packets_passed;
        uint64_t packets_dropped;
        uint64_t bytes_received;
        uint64_t bytes_dropped;
        uint64_t tcp_packets;
        uint64_t udp_packets;
        uint64_t icmp_packets;
        uint64_t other_packets;
    } *values = new decltype(*values)[num_cpus];
    
    if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
        for (int i = 0; i < num_cpus; i++) {
            stats.packets_received += values[i].packets_received;
            stats.packets_passed += values[i].packets_passed;
            stats.packets_dropped += values[i].packets_dropped;
            stats.bytes_received += values[i].bytes_received;
            stats.bytes_dropped += values[i].bytes_dropped;
        }
    }
    
    delete[] values;
#endif
    
    return stats;
}

void BPFLoader::ResetStats() {
#ifdef __linux__
    if (!stats_map_) {
        return;
    }
    
    int map_fd = bpf_map__fd(stats_map_);
    uint32_t key = 0;
    
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        return;
    }
    
    struct {
        uint64_t packets_received;
        uint64_t packets_passed;
        uint64_t packets_dropped;
        uint64_t bytes_received;
        uint64_t bytes_dropped;
        uint64_t tcp_packets;
        uint64_t udp_packets;
        uint64_t icmp_packets;
        uint64_t other_packets;
    } *values = new decltype(*values)[num_cpus]();
    
    bpf_map_update_elem(map_fd, &key, values, BPF_ANY);
    
    delete[] values;
#endif
}

int BPFLoader::GetInterfaceIndex(const std::string& interface) {
#ifdef __linux__
    return if_nametoindex(interface.c_str());
#else
    return -1;
#endif
}

uint32_t BPFLoader::IpStringToUint32(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

std::string BPFLoader::Uint32ToIpString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

} // namespace lumashield
