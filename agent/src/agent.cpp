/**
 * LumaShield Agent Implementation
 */

#include "agent.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>

#ifdef __linux__
#include <unistd.h>
#include <sys/utsname.h>
#endif

namespace lumashield {

Agent::Agent(const Config& config)
    : config_(config)
    , agent_id_(config.agent_id.empty() ? GenerateAgentId() : config.agent_id)
{
    // Initialize components
    bpf_loader_ = std::make_unique<BPFLoader>(config.bpf_object_path);
    grpc_client_ = std::make_unique<GRPCClient>(config.control_plane_addr, config.use_tls);
    stats_collector_ = std::make_unique<StatsCollector>(agent_id_);
}

Agent::~Agent() {
    Stop();
}

bool Agent::Start() {
    if (running_.load()) {
        return true;  // Already running
    }
    
    std::cout << "[Agent] Starting agent " << agent_id_ << std::endl;
    
    // Initialize BPF
    if (!InitializeBPF()) {
        std::cerr << "[Agent] Failed to initialize BPF" << std::endl;
        return false;
    }
    
    // Connect to Control Plane
    if (!ConnectToControlPlane()) {
        std::cerr << "[Agent] Failed to connect to Control Plane" << std::endl;
        // Continue anyway - will retry in background
    }
    
    running_.store(true);
    
    // Start event loop thread
    event_loop_thread_ = std::thread(&Agent::EventLoop, this);
    
    // Start heartbeat thread
    heartbeat_thread_ = std::thread([this]() {
        while (running_.load()) {
            if (connected_.load()) {
                SendHeartbeat();
            }
            std::this_thread::sleep_for(config_.heartbeat_interval);
        }
    });
    
    // Start stats reporting thread
    stats_thread_ = std::thread([this]() {
        while (running_.load()) {
            if (connected_.load()) {
                ReportStats();
            }
            std::this_thread::sleep_for(config_.stats_interval);
        }
    });
    
    std::cout << "[Agent] Agent started successfully" << std::endl;
    return true;
}

void Agent::Stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "[Agent] Stopping agent..." << std::endl;
    
    running_.store(false);
    
    // Wait for threads to finish
    if (event_loop_thread_.joinable()) {
        event_loop_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    if (stats_thread_.joinable()) {
        stats_thread_.join();
    }
    
    // Disconnect from Control Plane
    if (grpc_client_) {
        grpc_client_->Disconnect();
    }
    
    // Detach BPF programs
    if (bpf_loader_) {
        bpf_loader_->DetachAll();
    }
    
    connected_.store(false);
    
    std::cout << "[Agent] Agent stopped" << std::endl;
}

bool Agent::InitializeBPF() {
    std::cout << "[Agent] Loading BPF program from " << config_.bpf_object_path << std::endl;
    
    // Load BPF object
    if (!bpf_loader_->Load()) {
        return false;
    }
    
    // Attach XDP program to interface
    if (!bpf_loader_->AttachXDP(config_.interface, "xdp_firewall")) {
        return false;
    }
    
    std::cout << "[Agent] BPF program attached to " << config_.interface << std::endl;
    return true;
}

bool Agent::ConnectToControlPlane() {
    std::cout << "[Agent] Connecting to Control Plane at " << config_.control_plane_addr << std::endl;
    
    if (!grpc_client_->Connect()) {
        return false;
    }
    
    // Get hostname
    std::string hostname = config_.hostname;
    if (hostname.empty()) {
#ifdef __linux__
        char buf[256];
        if (gethostname(buf, sizeof(buf)) == 0) {
            hostname = buf;
        }
#endif
        if (hostname.empty()) {
            hostname = "unknown";
        }
    }
    
    // Register with Control Plane
    AgentInfo info{
        .id = agent_id_,
        .hostname = hostname,
        .ip_address = "",  // TODO: Get local IP
        .version = "1.0.0"
    };
    
    auto initial_rules = grpc_client_->Register(info);
    
    if (initial_rules.empty()) {
        std::cout << "[Agent] No initial rules received" << std::endl;
    } else {
        std::cout << "[Agent] Received " << initial_rules.size() << " initial rules" << std::endl;
        
        // Apply initial rules
        for (const auto& rule : initial_rules) {
            HandleRuleUpdate(rule);
        }
    }
    
    // Start rule streaming
    grpc_client_->StartRuleStream([this](const RuleUpdate& update) {
        HandleRuleUpdate(update);
    });
    
    // Set reconnect callback
    grpc_client_->SetReconnectCallback([this]() {
        std::cout << "[Agent] Reconnected to Control Plane" << std::endl;
        connected_.store(true);
    });
    
    connected_.store(true);
    std::cout << "[Agent] Connected to Control Plane" << std::endl;
    return true;
}

void Agent::EventLoop() {
    std::cout << "[Agent] Event loop started" << std::endl;
    
    while (running_.load()) {
        // Check connection status
        if (!connected_.load() && running_.load()) {
            std::cout << "[Agent] Attempting to reconnect to Control Plane..." << std::endl;
            if (ConnectToControlPlane()) {
                std::cout << "[Agent] Reconnected successfully" << std::endl;
            } else {
                std::this_thread::sleep_for(config_.reconnect_interval);
            }
        }
        
        // Collect stats from BPF
        if (bpf_loader_ && bpf_loader_->IsLoaded()) {
            auto bpf_stats = bpf_loader_->GetStats();
            stats_collector_->UpdateBPFStats(
                bpf_stats.packets_received,
                bpf_stats.packets_passed,
                bpf_stats.packets_dropped,
                bpf_stats.bytes_received,
                bpf_stats.bytes_dropped
            );
        }
        
        // Collect system resource usage
        stats_collector_->CollectResourceUsage();
        
        // Sleep a bit
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "[Agent] Event loop stopped" << std::endl;
}

void Agent::HandleRuleUpdate(const RuleUpdate& update) {
    std::cout << "[Agent] Received rule update: " 
              << (update.type == RuleUpdate::Type::ADD ? "ADD" : 
                  update.type == RuleUpdate::Type::REMOVE ? "REMOVE" : "MODIFY")
              << " " << update.target << std::endl;
    
    switch (update.type) {
        case RuleUpdate::Type::ADD:
            if (update.rule_type == "ip_block") {
                if (bpf_loader_->AddToBlacklist(update.target)) {
                    std::cout << "[Agent] Added " << update.target << " to blacklist" << std::endl;
                }
            }
            break;
            
        case RuleUpdate::Type::REMOVE:
            if (update.rule_type == "ip_block") {
                if (bpf_loader_->RemoveFromBlacklist(update.target)) {
                    std::cout << "[Agent] Removed " << update.target << " from blacklist" << std::endl;
                }
            }
            break;
            
        case RuleUpdate::Type::MODIFY:
            // For modify, remove and re-add
            if (update.rule_type == "ip_block") {
                bpf_loader_->RemoveFromBlacklist(update.target);
                bpf_loader_->AddToBlacklist(update.target);
            }
            break;
    }
}

void Agent::SendHeartbeat() {
    if (!grpc_client_ || !grpc_client_->IsConnected()) {
        return;
    }
    
    if (!grpc_client_->SendHeartbeat(agent_id_)) {
        std::cerr << "[Agent] Failed to send heartbeat" << std::endl;
        connected_.store(false);
    }
}

void Agent::ReportStats() {
    if (!grpc_client_ || !grpc_client_->IsConnected()) {
        return;
    }
    
    auto stats = stats_collector_->GetDelta();
    
    if (!grpc_client_->SendStats(stats)) {
        std::cerr << "[Agent] Failed to send stats" << std::endl;
    }
}

bool Agent::AddToBlacklist(const std::string& ip) {
    if (!bpf_loader_) return false;
    return bpf_loader_->AddToBlacklist(ip);
}

bool Agent::RemoveFromBlacklist(const std::string& ip) {
    if (!bpf_loader_) return false;
    return bpf_loader_->RemoveFromBlacklist(ip);
}

AgentStats Agent::GetStats() const {
    if (!stats_collector_) return AgentStats{};
    return stats_collector_->GetSnapshot();
}

std::string Agent::GenerateAgentId() {
    // Generate a UUID-like ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "agent-";
    
    const char* hex = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        ss << hex[dis(gen)];
    }
    ss << "-";
    for (int i = 0; i < 4; i++) {
        ss << hex[dis(gen)];
    }
    
    return ss.str();
}

} // namespace lumashield
