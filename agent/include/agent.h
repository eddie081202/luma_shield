#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <functional>

#include "config.h"
#include "bpf_loader.h"
#include "grpc/client.h"
#include "stats_collector.h"

namespace lumashield {

/**
 * @brief Main Agent class that orchestrates all components
 * 
 * The Agent is responsible for:
 * - Loading and managing BPF programs
 * - Communicating with the Control Plane via gRPC
 * - Collecting and reporting statistics
 * - Applying firewall rules
 */
class Agent {
public:
    /**
     * @brief Construct a new Agent
     * @param config Configuration object
     */
    explicit Agent(const Config& config);
    
    /**
     * @brief Destructor - ensures clean shutdown
     */
    ~Agent();

    // Disable copy
    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    /**
     * @brief Start the agent
     * @return true if started successfully
     */
    bool Start();

    /**
     * @brief Stop the agent
     */
    void Stop();

    /**
     * @brief Check if agent is running
     */
    bool IsRunning() const { return running_.load(); }

    /**
     * @brief Get agent ID
     */
    const std::string& GetAgentId() const { return agent_id_; }

    /**
     * @brief Add an IP to the blacklist
     * @param ip IP address to block
     * @return true if added successfully
     */
    bool AddToBlacklist(const std::string& ip);

    /**
     * @brief Remove an IP from the blacklist
     * @param ip IP address to unblock
     * @return true if removed successfully
     */
    bool RemoveFromBlacklist(const std::string& ip);

    /**
     * @brief Get current statistics
     */
    AgentStats GetStats() const;

private:
    /**
     * @brief Initialize BPF programs
     */
    bool InitializeBPF();

    /**
     * @brief Connect to Control Plane
     */
    bool ConnectToControlPlane();

    /**
     * @brief Main event loop
     */
    void EventLoop();

    /**
     * @brief Handle rule updates from Control Plane
     */
    void HandleRuleUpdate(const RuleUpdate& update);

    /**
     * @brief Send heartbeat to Control Plane
     */
    void SendHeartbeat();

    /**
     * @brief Report statistics to Control Plane
     */
    void ReportStats();

    /**
     * @brief Generate unique agent ID
     */
    static std::string GenerateAgentId();

private:
    Config config_;
    std::string agent_id_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};

    // Components
    std::unique_ptr<BPFLoader> bpf_loader_;
    std::unique_ptr<GRPCClient> grpc_client_;
    std::unique_ptr<StatsCollector> stats_collector_;

    // Worker threads
    std::thread event_loop_thread_;
    std::thread heartbeat_thread_;
    std::thread stats_thread_;
};

} // namespace lumashield
