#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>

// Forward declarations for libbpf types
struct bpf_object;
struct bpf_program;
struct bpf_map;
struct bpf_link;

namespace lumashield {

/**
 * @brief Statistics from BPF programs
 */
struct BPFStats {
    uint64_t packets_received;
    uint64_t packets_passed;
    uint64_t packets_dropped;
    uint64_t bytes_received;
    uint64_t bytes_dropped;
};

/**
 * @brief Blacklist entry for BPF map
 */
struct BlacklistEntry {
    uint32_t ip;           // IP address in network byte order
    uint64_t drop_count;   // Number of packets dropped
    uint64_t last_seen;    // Timestamp of last packet
};

/**
 * @brief XDP action codes
 */
enum class XDPAction : int {
    ABORTED = 0,
    DROP = 1,
    PASS = 2,
    TX = 3,
    REDIRECT = 4
};

/**
 * @brief BPF program loader and manager
 * 
 * Handles loading, attaching, and managing eBPF/XDP programs
 */
class BPFLoader {
public:
    /**
     * @brief Construct BPF loader
     * @param bpf_object_path Path to compiled BPF object file
     */
    explicit BPFLoader(const std::string& bpf_object_path);
    
    /**
     * @brief Destructor - detaches all programs
     */
    ~BPFLoader();

    // Disable copy
    BPFLoader(const BPFLoader&) = delete;
    BPFLoader& operator=(const BPFLoader&) = delete;

    /**
     * @brief Load the BPF object file
     * @return true if loaded successfully
     */
    bool Load();

    /**
     * @brief Attach XDP program to network interface
     * @param interface Network interface name (e.g., "eth0")
     * @param program_name Name of the XDP program in the object
     * @return true if attached successfully
     */
    bool AttachXDP(const std::string& interface, const std::string& program_name);

    /**
     * @brief Detach XDP program from interface
     * @param interface Network interface name
     */
    void DetachXDP(const std::string& interface);

    /**
     * @brief Detach all XDP programs
     */
    void DetachAll();

    /**
     * @brief Add IP to blacklist map
     * @param ip IP address string (e.g., "192.168.1.1")
     * @return true if added successfully
     */
    bool AddToBlacklist(const std::string& ip);

    /**
     * @brief Add IP to blacklist map (raw format)
     * @param ip IP address in host byte order
     * @return true if added successfully
     */
    bool AddToBlacklist(uint32_t ip);

    /**
     * @brief Remove IP from blacklist map
     * @param ip IP address string
     * @return true if removed successfully
     */
    bool RemoveFromBlacklist(const std::string& ip);

    /**
     * @brief Remove IP from blacklist map (raw format)
     * @param ip IP address in host byte order
     * @return true if removed successfully
     */
    bool RemoveFromBlacklist(uint32_t ip);

    /**
     * @brief Check if IP is in blacklist
     * @param ip IP address string
     * @return true if blacklisted
     */
    bool IsBlacklisted(const std::string& ip) const;

    /**
     * @brief Get all blacklisted IPs
     * @return Vector of IP addresses
     */
    std::vector<uint32_t> GetBlacklist() const;

    /**
     * @brief Get blacklist entry details
     * @param ip IP address
     * @return Blacklist entry or nullptr if not found
     */
    std::unique_ptr<BlacklistEntry> GetBlacklistEntry(uint32_t ip) const;

    /**
     * @brief Get current statistics
     * @return BPF statistics
     */
    BPFStats GetStats() const;

    /**
     * @brief Reset statistics counters
     */
    void ResetStats();

    /**
     * @brief Check if BPF is loaded
     */
    bool IsLoaded() const { return loaded_; }

    /**
     * @brief Get interface index by name
     */
    static int GetInterfaceIndex(const std::string& interface);

    /**
     * @brief Convert IP string to uint32_t
     */
    static uint32_t IpStringToUint32(const std::string& ip);

    /**
     * @brief Convert uint32_t to IP string
     */
    static std::string Uint32ToIpString(uint32_t ip);

private:
    /**
     * @brief Get BPF map by name
     */
    struct bpf_map* GetMap(const std::string& name) const;

    /**
     * @brief Get BPF program by name
     */
    struct bpf_program* GetProgram(const std::string& name) const;

private:
    std::string bpf_object_path_;
    bool loaded_ = false;

    // libbpf handles
    struct bpf_object* obj_ = nullptr;
    
    // Maps
    struct bpf_map* blacklist_map_ = nullptr;
    struct bpf_map* stats_map_ = nullptr;

    // Attached programs
    std::unordered_map<std::string, struct bpf_link*> attached_links_;
};

} // namespace lumashield
