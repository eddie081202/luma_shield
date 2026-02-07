#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace lumashield {

/**
 * @brief Statistics collected by the agent
 */
struct AgentStats {
    std::string agent_id;
    
    // Packet statistics
    uint64_t packets_received = 0;
    uint64_t packets_passed = 0;
    uint64_t packets_dropped = 0;
    
    // Byte statistics
    uint64_t bytes_received = 0;
    uint64_t bytes_dropped = 0;
    
    // Connection statistics
    uint64_t active_connections = 0;
    
    // Resource usage
    double cpu_usage = 0.0;
    double memory_usage = 0.0;
    
    // Timestamp
    std::chrono::system_clock::time_point timestamp;
    
    /**
     * @brief Calculate packets per second
     */
    double GetPacketsPerSecond(const AgentStats& previous) const;
    
    /**
     * @brief Calculate drop rate
     */
    double GetDropRate() const;
};

/**
 * @brief Collects and aggregates statistics from various sources
 */
class StatsCollector {
public:
    /**
     * @brief Construct stats collector
     * @param agent_id Agent identifier for tagging stats
     */
    explicit StatsCollector(const std::string& agent_id);
    
    /**
     * @brief Destructor
     */
    ~StatsCollector() = default;

    /**
     * @brief Update BPF statistics
     * @param packets_received Total packets seen
     * @param packets_passed Packets allowed
     * @param packets_dropped Packets blocked
     * @param bytes_received Total bytes seen
     * @param bytes_dropped Bytes blocked
     */
    void UpdateBPFStats(
        uint64_t packets_received,
        uint64_t packets_passed,
        uint64_t packets_dropped,
        uint64_t bytes_received,
        uint64_t bytes_dropped
    );

    /**
     * @brief Update connection count
     */
    void UpdateConnectionCount(uint64_t count);

    /**
     * @brief Collect current system resource usage
     */
    void CollectResourceUsage();

    /**
     * @brief Get current snapshot of all statistics
     */
    AgentStats GetSnapshot() const;

    /**
     * @brief Get delta since last snapshot
     * @return Stats representing changes since last call
     */
    AgentStats GetDelta();

    /**
     * @brief Reset all counters
     */
    void Reset();

    /**
     * @brief Record a dropped packet by rule
     * @param rule_id Rule that caused the drop
     */
    void RecordDropByRule(const std::string& rule_id);

    /**
     * @brief Get drops by rule
     */
    std::unordered_map<std::string, uint64_t> GetDropsByRule() const;

private:
    /**
     * @brief Get CPU usage percentage
     */
    static double GetCPUUsage();

    /**
     * @brief Get memory usage percentage
     */
    static double GetMemoryUsage();

private:
    std::string agent_id_;
    mutable std::mutex mutex_;

    // Current counters
    std::atomic<uint64_t> packets_received_{0};
    std::atomic<uint64_t> packets_passed_{0};
    std::atomic<uint64_t> packets_dropped_{0};
    std::atomic<uint64_t> bytes_received_{0};
    std::atomic<uint64_t> bytes_dropped_{0};
    std::atomic<uint64_t> active_connections_{0};
    
    std::atomic<double> cpu_usage_{0.0};
    std::atomic<double> memory_usage_{0.0};

    // Previous snapshot for delta calculation
    AgentStats last_snapshot_;

    // Drops by rule
    std::unordered_map<std::string, std::atomic<uint64_t>> drops_by_rule_;
    mutable std::mutex drops_mutex_;
};

} // namespace lumashield
