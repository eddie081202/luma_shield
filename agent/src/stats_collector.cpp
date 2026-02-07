/**
 * Stats Collector Implementation
 */

#include "stats_collector.h"

#include <fstream>
#include <sstream>
#include <string>

#ifdef __linux__
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace lumashield {

double AgentStats::GetPacketsPerSecond(const AgentStats& previous) const {
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        timestamp - previous.timestamp
    ).count();
    
    if (duration <= 0) return 0.0;
    
    return static_cast<double>(packets_received - previous.packets_received) / duration;
}

double AgentStats::GetDropRate() const {
    if (packets_received == 0) return 0.0;
    return static_cast<double>(packets_dropped) / packets_received * 100.0;
}

StatsCollector::StatsCollector(const std::string& agent_id)
    : agent_id_(agent_id)
{
    last_snapshot_.agent_id = agent_id;
    last_snapshot_.timestamp = std::chrono::system_clock::now();
}

void StatsCollector::UpdateBPFStats(
    uint64_t packets_received,
    uint64_t packets_passed,
    uint64_t packets_dropped,
    uint64_t bytes_received,
    uint64_t bytes_dropped)
{
    packets_received_.store(packets_received, std::memory_order_relaxed);
    packets_passed_.store(packets_passed, std::memory_order_relaxed);
    packets_dropped_.store(packets_dropped, std::memory_order_relaxed);
    bytes_received_.store(bytes_received, std::memory_order_relaxed);
    bytes_dropped_.store(bytes_dropped, std::memory_order_relaxed);
}

void StatsCollector::UpdateConnectionCount(uint64_t count) {
    active_connections_.store(count, std::memory_order_relaxed);
}

void StatsCollector::CollectResourceUsage() {
    cpu_usage_.store(GetCPUUsage(), std::memory_order_relaxed);
    memory_usage_.store(GetMemoryUsage(), std::memory_order_relaxed);
}

AgentStats StatsCollector::GetSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    AgentStats stats;
    stats.agent_id = agent_id_;
    stats.packets_received = packets_received_.load(std::memory_order_relaxed);
    stats.packets_passed = packets_passed_.load(std::memory_order_relaxed);
    stats.packets_dropped = packets_dropped_.load(std::memory_order_relaxed);
    stats.bytes_received = bytes_received_.load(std::memory_order_relaxed);
    stats.bytes_dropped = bytes_dropped_.load(std::memory_order_relaxed);
    stats.active_connections = active_connections_.load(std::memory_order_relaxed);
    stats.cpu_usage = cpu_usage_.load(std::memory_order_relaxed);
    stats.memory_usage = memory_usage_.load(std::memory_order_relaxed);
    stats.timestamp = std::chrono::system_clock::now();
    
    return stats;
}

AgentStats StatsCollector::GetDelta() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    AgentStats current = GetSnapshot();
    
    AgentStats delta;
    delta.agent_id = agent_id_;
    delta.packets_received = current.packets_received - last_snapshot_.packets_received;
    delta.packets_passed = current.packets_passed - last_snapshot_.packets_passed;
    delta.packets_dropped = current.packets_dropped - last_snapshot_.packets_dropped;
    delta.bytes_received = current.bytes_received - last_snapshot_.bytes_received;
    delta.bytes_dropped = current.bytes_dropped - last_snapshot_.bytes_dropped;
    delta.active_connections = current.active_connections;
    delta.cpu_usage = current.cpu_usage;
    delta.memory_usage = current.memory_usage;
    delta.timestamp = current.timestamp;
    
    last_snapshot_ = current;
    
    return delta;
}

void StatsCollector::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    packets_received_.store(0, std::memory_order_relaxed);
    packets_passed_.store(0, std::memory_order_relaxed);
    packets_dropped_.store(0, std::memory_order_relaxed);
    bytes_received_.store(0, std::memory_order_relaxed);
    bytes_dropped_.store(0, std::memory_order_relaxed);
    active_connections_.store(0, std::memory_order_relaxed);
    
    last_snapshot_ = AgentStats{};
    last_snapshot_.agent_id = agent_id_;
    last_snapshot_.timestamp = std::chrono::system_clock::now();
    
    std::lock_guard<std::mutex> drops_lock(drops_mutex_);
    drops_by_rule_.clear();
}

void StatsCollector::RecordDropByRule(const std::string& rule_id) {
    std::lock_guard<std::mutex> lock(drops_mutex_);
    
    auto it = drops_by_rule_.find(rule_id);
    if (it != drops_by_rule_.end()) {
        it->second.fetch_add(1, std::memory_order_relaxed);
    } else {
        drops_by_rule_[rule_id].store(1, std::memory_order_relaxed);
    }
}

std::unordered_map<std::string, uint64_t> StatsCollector::GetDropsByRule() const {
    std::lock_guard<std::mutex> lock(drops_mutex_);
    
    std::unordered_map<std::string, uint64_t> result;
    for (const auto& [rule_id, count] : drops_by_rule_) {
        result[rule_id] = count.load(std::memory_order_relaxed);
    }
    return result;
}

double StatsCollector::GetCPUUsage() {
#ifdef __linux__
    static long prev_idle = 0;
    static long prev_total = 0;
    
    std::ifstream stat_file("/proc/stat");
    if (!stat_file.is_open()) {
        return 0.0;
    }
    
    std::string line;
    std::getline(stat_file, line);
    
    // Parse CPU line: cpu user nice system idle iowait irq softirq
    std::istringstream iss(line);
    std::string cpu;
    long user, nice, system, idle, iowait, irq, softirq;
    
    iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq;
    
    long total = user + nice + system + idle + iowait + irq + softirq;
    long idle_time = idle + iowait;
    
    // Calculate CPU usage
    long total_diff = total - prev_total;
    long idle_diff = idle_time - prev_idle;
    
    prev_total = total;
    prev_idle = idle_time;
    
    if (total_diff == 0) {
        return 0.0;
    }
    
    return 100.0 * (1.0 - static_cast<double>(idle_diff) / total_diff);
#else
    return 0.0;
#endif
}

double StatsCollector::GetMemoryUsage() {
#ifdef __linux__
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        return 0.0;
    }
    
    unsigned long total = info.totalram * info.mem_unit;
    unsigned long free = info.freeram * info.mem_unit;
    unsigned long used = total - free;
    
    return 100.0 * static_cast<double>(used) / total;
#else
    return 0.0;
#endif
}

} // namespace lumashield
