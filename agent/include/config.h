#pragma once

#include <string>
#include <vector>
#include <chrono>

namespace lumashield {

/**
 * @brief Agent configuration
 */
struct Config {
    // Agent identification
    std::string agent_id;           // Optional: auto-generated if empty
    std::string hostname;           // Optional: auto-detected if empty
    
    // Control Plane connection
    std::string control_plane_addr; // gRPC address (e.g., "localhost:50051")
    bool use_tls = false;           // Use TLS for gRPC
    std::string tls_cert_path;      // Path to TLS certificate
    std::string tls_key_path;       // Path to TLS private key
    std::string tls_ca_path;        // Path to CA certificate
    
    // Network interface
    std::string interface;          // Network interface to attach to (e.g., "eth0")
    
    // BPF settings
    std::string bpf_object_path;    // Path to compiled BPF object
    bool xdp_native_mode = false;   // Use native XDP mode (requires driver support)
    
    // Timing settings
    std::chrono::milliseconds heartbeat_interval{30000};  // 30 seconds
    std::chrono::milliseconds stats_interval{10000};      // 10 seconds
    std::chrono::milliseconds reconnect_interval{5000};   // 5 seconds
    
    // Logging
    std::string log_level = "info"; // debug, info, warn, error
    std::string log_file;           // Optional: log to file
    
    // Limits
    size_t max_blacklist_size = 100000;  // Maximum IPs in blacklist
    
    /**
     * @brief Load configuration from file
     * @param path Path to config file (YAML or JSON)
     * @return Config object
     */
    static Config LoadFromFile(const std::string& path);
    
    /**
     * @brief Load configuration from environment variables
     * @return Config object
     */
    static Config LoadFromEnv();
    
    /**
     * @brief Get default configuration
     */
    static Config Default();
    
    /**
     * @brief Validate configuration
     * @return Error message if invalid, empty string if valid
     */
    std::string Validate() const;
};

} // namespace lumashield
