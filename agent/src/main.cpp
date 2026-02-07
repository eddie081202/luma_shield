/**
 * LumaShield Agent - Main Entry Point
 * 
 * This is the main entry point for the LumaShield XDP agent.
 * It loads configuration, initializes the agent, and runs the main loop.
 */

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>

#include "agent.h"
#include "config.h"

namespace {
    // Global agent pointer for signal handling
    lumashield::Agent* g_agent = nullptr;
    
    // Signal handler for graceful shutdown
    void signal_handler(int signum) {
        std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
        if (g_agent) {
            g_agent->Stop();
        }
    }
    
    // Print usage information
    void print_usage(const char* program_name) {
        std::cout << "Usage: " << program_name << " [options]\n"
                  << "\n"
                  << "Options:\n"
                  << "  -c, --config <path>     Path to configuration file\n"
                  << "  -i, --interface <name>  Network interface to attach to\n"
                  << "  -s, --server <addr>     Control Plane address (host:port)\n"
                  << "  -b, --bpf <path>        Path to BPF object file\n"
                  << "  -l, --log-level <level> Log level (debug, info, warn, error)\n"
                  << "  -h, --help              Show this help message\n"
                  << "  -v, --version           Show version information\n"
                  << "\n"
                  << "Environment variables:\n"
                  << "  LUMASHIELD_CONFIG           Path to configuration file\n"
                  << "  LUMASHIELD_INTERFACE        Network interface\n"
                  << "  LUMASHIELD_CONTROL_PLANE    Control Plane address\n"
                  << "  LUMASHIELD_BPF_PATH         Path to BPF object file\n"
                  << "  LUMASHIELD_LOG_LEVEL        Log level\n"
                  << std::endl;
    }
    
    void print_version() {
        std::cout << "LumaShield Agent v1.0.0\n"
                  << "Built with XDP/eBPF support\n"
                  << "Copyright (c) 2024 LumaShield\n"
                  << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Default configuration
    lumashield::Config config = lumashield::Config::Default();
    std::string config_file;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            print_version();
            return 0;
        }
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        }
        else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            config.interface = argv[++i];
        }
        else if ((arg == "-s" || arg == "--server") && i + 1 < argc) {
            config.control_plane_addr = argv[++i];
        }
        else if ((arg == "-b" || arg == "--bpf") && i + 1 < argc) {
            config.bpf_object_path = argv[++i];
        }
        else if ((arg == "-l" || arg == "--log-level") && i + 1 < argc) {
            config.log_level = argv[++i];
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Load configuration from file if specified
    if (!config_file.empty()) {
        try {
            config = lumashield::Config::LoadFromFile(config_file);
        } catch (const std::exception& e) {
            std::cerr << "Failed to load config file: " << e.what() << std::endl;
            return 1;
        }
    }
    
    // Override with environment variables
    lumashield::Config env_config = lumashield::Config::LoadFromEnv();
    if (!env_config.interface.empty()) config.interface = env_config.interface;
    if (!env_config.control_plane_addr.empty()) config.control_plane_addr = env_config.control_plane_addr;
    if (!env_config.bpf_object_path.empty()) config.bpf_object_path = env_config.bpf_object_path;
    if (!env_config.log_level.empty()) config.log_level = env_config.log_level;
    
    // Validate configuration
    std::string validation_error = config.Validate();
    if (!validation_error.empty()) {
        std::cerr << "Configuration error: " << validation_error << std::endl;
        return 1;
    }
    
    // Print startup information
    std::cout << "========================================\n"
              << "       LumaShield XDP Agent v1.0.0      \n"
              << "========================================\n"
              << "\n"
              << "Configuration:\n"
              << "  Interface:      " << config.interface << "\n"
              << "  Control Plane:  " << config.control_plane_addr << "\n"
              << "  BPF Object:     " << config.bpf_object_path << "\n"
              << "  Log Level:      " << config.log_level << "\n"
              << "\n";
    
    // Setup signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    // Create and start agent
    try {
        lumashield::Agent agent(config);
        g_agent = &agent;
        
        if (!agent.Start()) {
            std::cerr << "Failed to start agent" << std::endl;
            return 1;
        }
        
        std::cout << "Agent started successfully with ID: " << agent.GetAgentId() << "\n"
                  << "Press Ctrl+C to stop...\n" << std::endl;
        
        // Wait for shutdown
        while (agent.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        g_agent = nullptr;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "Agent stopped gracefully" << std::endl;
    return 0;
}
