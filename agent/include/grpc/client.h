#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include <condition_variable>

namespace lumashield {

// Forward declarations
struct AgentStats;

/**
 * @brief Rule update received from Control Plane
 */
struct RuleUpdate {
    enum class Type {
        ADD,
        REMOVE,
        MODIFY
    };

    Type type;
    std::string rule_id;
    std::string rule_type;    // "ip_block", "cidr_block", etc.
    std::string target;       // IP, CIDR, or pattern
    std::string action;       // "drop", "reject", "log"
    std::string reason;
    int priority;
};

/**
 * @brief Agent information for registration
 */
struct AgentInfo {
    std::string id;
    std::string hostname;
    std::string ip_address;
    std::string version;
};

/**
 * @brief Callback type for rule updates
 */
using RuleUpdateCallback = std::function<void(const RuleUpdate&)>;

/**
 * @brief gRPC client for communicating with Control Plane
 */
class GRPCClient {
public:
    /**
     * @brief Construct gRPC client
     * @param server_addr Control Plane gRPC address
     * @param use_tls Use TLS encryption
     */
    GRPCClient(const std::string& server_addr, bool use_tls = false);
    
    /**
     * @brief Destructor
     */
    ~GRPCClient();

    // Disable copy
    GRPCClient(const GRPCClient&) = delete;
    GRPCClient& operator=(const GRPCClient&) = delete;

    /**
     * @brief Connect to the Control Plane
     * @return true if connected successfully
     */
    bool Connect();

    /**
     * @brief Disconnect from Control Plane
     */
    void Disconnect();

    /**
     * @brief Check if connected
     */
    bool IsConnected() const { return connected_.load(); }

    /**
     * @brief Register agent with Control Plane
     * @param info Agent information
     * @return Initial rules to apply, empty vector on failure
     */
    std::vector<RuleUpdate> Register(const AgentInfo& info);

    /**
     * @brief Send heartbeat
     * @param agent_id Agent identifier
     * @return true if acknowledged
     */
    bool SendHeartbeat(const std::string& agent_id);

    /**
     * @brief Send statistics to Control Plane
     * @param stats Statistics to report
     * @return true if sent successfully
     */
    bool SendStats(const AgentStats& stats);

    /**
     * @brief Start streaming rule updates
     * @param callback Callback for rule updates
     */
    void StartRuleStream(RuleUpdateCallback callback);

    /**
     * @brief Stop streaming rule updates
     */
    void StopRuleStream();

    /**
     * @brief Set reconnection callback
     */
    void SetReconnectCallback(std::function<void()> callback);

    /**
     * @brief Get server address
     */
    const std::string& GetServerAddr() const { return server_addr_; }

private:
    /**
     * @brief Stream worker thread function
     */
    void StreamWorker();

    /**
     * @brief Reconnection loop
     */
    void ReconnectLoop();

private:
    std::string server_addr_;
    bool use_tls_;
    
    std::atomic<bool> connected_{false};
    std::atomic<bool> streaming_{false};
    std::atomic<bool> should_reconnect_{true};

    // gRPC channel and stubs (opaque pointers - actual gRPC types in .cpp)
    std::shared_ptr<void> channel_;
    std::shared_ptr<void> stub_;

    // Streaming
    std::thread stream_thread_;
    RuleUpdateCallback rule_callback_;
    std::mutex callback_mutex_;

    // Stats queue for sending
    std::queue<AgentStats> stats_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    // Reconnection
    std::function<void()> reconnect_callback_;
    std::thread reconnect_thread_;
};

} // namespace lumashield
