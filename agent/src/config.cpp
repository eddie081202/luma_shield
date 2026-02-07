/**
 * Configuration Implementation
 */

#include "config.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

namespace lumashield {

Config Config::Default() {
    Config config;
    
    config.agent_id = "";  // Will be auto-generated
    config.hostname = "";  // Will be auto-detected
    
    config.control_plane_addr = "localhost:50051";
    config.use_tls = false;
    
    config.interface = "eth0";
    config.bpf_object_path = "/usr/share/lumashield/bpf/firewall.bpf.o";
    config.xdp_native_mode = false;
    
    config.heartbeat_interval = std::chrono::milliseconds(30000);
    config.stats_interval = std::chrono::milliseconds(10000);
    config.reconnect_interval = std::chrono::milliseconds(5000);
    
    config.log_level = "info";
    config.log_file = "";
    
    config.max_blacklist_size = 100000;
    
    return config;
}

Config Config::LoadFromEnv() {
    Config config = Default();
    
    // Agent settings
    if (const char* val = std::getenv("LUMASHIELD_AGENT_ID")) {
        config.agent_id = val;
    }
    if (const char* val = std::getenv("LUMASHIELD_HOSTNAME")) {
        config.hostname = val;
    }
    
    // Control Plane settings
    if (const char* val = std::getenv("LUMASHIELD_CONTROL_PLANE")) {
        config.control_plane_addr = val;
    }
    if (const char* val = std::getenv("LUMASHIELD_USE_TLS")) {
        config.use_tls = (std::string(val) == "true" || std::string(val) == "1");
    }
    if (const char* val = std::getenv("LUMASHIELD_TLS_CERT")) {
        config.tls_cert_path = val;
    }
    if (const char* val = std::getenv("LUMASHIELD_TLS_KEY")) {
        config.tls_key_path = val;
    }
    if (const char* val = std::getenv("LUMASHIELD_TLS_CA")) {
        config.tls_ca_path = val;
    }
    
    // Network settings
    if (const char* val = std::getenv("LUMASHIELD_INTERFACE")) {
        config.interface = val;
    }
    
    // BPF settings
    if (const char* val = std::getenv("LUMASHIELD_BPF_PATH")) {
        config.bpf_object_path = val;
    }
    if (const char* val = std::getenv("LUMASHIELD_XDP_NATIVE")) {
        config.xdp_native_mode = (std::string(val) == "true" || std::string(val) == "1");
    }
    
    // Timing settings
    if (const char* val = std::getenv("LUMASHIELD_HEARTBEAT_INTERVAL")) {
        config.heartbeat_interval = std::chrono::milliseconds(std::stoi(val));
    }
    if (const char* val = std::getenv("LUMASHIELD_STATS_INTERVAL")) {
        config.stats_interval = std::chrono::milliseconds(std::stoi(val));
    }
    
    // Logging
    if (const char* val = std::getenv("LUMASHIELD_LOG_LEVEL")) {
        config.log_level = val;
    }
    if (const char* val = std::getenv("LUMASHIELD_LOG_FILE")) {
        config.log_file = val;
    }
    
    return config;
}

Config Config::LoadFromFile(const std::string& path) {
    Config config = Default();
    
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open config file: " + path);
    }
    
    std::string line;
    int line_number = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Find key=value separator
        size_t sep_pos = line.find('=');
        if (sep_pos == std::string::npos) {
            continue;  // Skip malformed lines
        }
        
        std::string key = line.substr(0, sep_pos);
        std::string value = line.substr(sep_pos + 1);
        
        // Trim whitespace
        auto trim = [](std::string& s) {
            size_t start = s.find_first_not_of(" \t\r\n");
            size_t end = s.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) {
                s = "";
            } else {
                s = s.substr(start, end - start + 1);
            }
        };
        
        trim(key);
        trim(value);
        
        // Parse values
        if (key == "agent_id") {
            config.agent_id = value;
        } else if (key == "hostname") {
            config.hostname = value;
        } else if (key == "control_plane_addr") {
            config.control_plane_addr = value;
        } else if (key == "use_tls") {
            config.use_tls = (value == "true" || value == "1");
        } else if (key == "tls_cert_path") {
            config.tls_cert_path = value;
        } else if (key == "tls_key_path") {
            config.tls_key_path = value;
        } else if (key == "tls_ca_path") {
            config.tls_ca_path = value;
        } else if (key == "interface") {
            config.interface = value;
        } else if (key == "bpf_object_path") {
            config.bpf_object_path = value;
        } else if (key == "xdp_native_mode") {
            config.xdp_native_mode = (value == "true" || value == "1");
        } else if (key == "heartbeat_interval") {
            config.heartbeat_interval = std::chrono::milliseconds(std::stoi(value));
        } else if (key == "stats_interval") {
            config.stats_interval = std::chrono::milliseconds(std::stoi(value));
        } else if (key == "reconnect_interval") {
            config.reconnect_interval = std::chrono::milliseconds(std::stoi(value));
        } else if (key == "log_level") {
            config.log_level = value;
        } else if (key == "log_file") {
            config.log_file = value;
        } else if (key == "max_blacklist_size") {
            config.max_blacklist_size = std::stoull(value);
        }
    }
    
    return config;
}

std::string Config::Validate() const {
    std::stringstream errors;
    
    // Check required fields
    if (interface.empty()) {
        errors << "Network interface is required\n";
    }
    
    if (control_plane_addr.empty()) {
        errors << "Control Plane address is required\n";
    }
    
    if (bpf_object_path.empty()) {
        errors << "BPF object path is required\n";
    }
    
    // Validate TLS configuration
    if (use_tls) {
        if (tls_cert_path.empty()) {
            errors << "TLS certificate path is required when TLS is enabled\n";
        }
        if (tls_key_path.empty()) {
            errors << "TLS key path is required when TLS is enabled\n";
        }
    }
    
    // Validate timing
    if (heartbeat_interval.count() < 1000) {
        errors << "Heartbeat interval must be at least 1000ms\n";
    }
    
    if (stats_interval.count() < 1000) {
        errors << "Stats interval must be at least 1000ms\n";
    }
    
    // Validate log level
    if (log_level != "debug" && log_level != "info" && 
        log_level != "warn" && log_level != "error") {
        errors << "Invalid log level: " << log_level << "\n";
    }
    
    return errors.str();
}

} // namespace lumashield
