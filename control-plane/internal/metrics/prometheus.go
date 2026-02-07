package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Agent metrics
	ActiveAgents = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "lumashield",
		Name:      "active_agents",
		Help:      "Number of currently active agents",
	})

	RegisteredAgents = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "registered_agents_total",
		Help:      "Total number of agents that have registered",
	})

	AgentHeartbeats = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "agent_heartbeats_total",
		Help:      "Total heartbeats received from agents",
	}, []string{"agent_id"})

	// Packet metrics (aggregated from agents)
	PacketsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "packets_processed_total",
		Help:      "Total packets processed by agents",
	}, []string{"agent_id"})

	PacketsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "packets_dropped_total",
		Help:      "Total packets dropped by agents",
	}, []string{"agent_id", "reason"})

	BytesProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "bytes_processed_total",
		Help:      "Total bytes processed by agents",
	}, []string{"agent_id"})

	BytesDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "bytes_dropped_total",
		Help:      "Total bytes dropped by agents",
	}, []string{"agent_id"})

	// Rule metrics
	TotalRules = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "lumashield",
		Name:      "rules_total",
		Help:      "Total number of active rules",
	})

	RulesCreated = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "rules_created_total",
		Help:      "Total number of rules created",
	})

	RulesDeleted = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "rules_deleted_total",
		Help:      "Total number of rules deleted",
	})

	RuleDistributionLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "lumashield",
		Name:      "rule_distribution_latency_seconds",
		Help:      "Time to distribute a rule to all agents",
		Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 15), // 0.1ms to ~3s
	})

	// Blacklist metrics
	BlacklistSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "lumashield",
		Name:      "blacklist_size",
		Help:      "Number of IPs in the blacklist",
	})

	BlacklistHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "blacklist_hits_total",
		Help:      "Total hits on blacklisted IPs",
	}, []string{"ip"})

	// API metrics
	APIRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "api_requests_total",
		Help:      "Total API requests",
	}, []string{"method", "endpoint", "status"})

	APILatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "lumashield",
		Name:      "api_latency_seconds",
		Help:      "API request latency",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "endpoint"})

	// gRPC metrics
	GRPCConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "lumashield",
		Name:      "grpc_active_connections",
		Help:      "Number of active gRPC connections",
	})

	GRPCStreamMessages = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "grpc_stream_messages_total",
		Help:      "Total messages sent/received on gRPC streams",
	}, []string{"direction", "message_type"})

	// Redis metrics
	RedisOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lumashield",
		Name:      "redis_operations_total",
		Help:      "Total Redis operations",
	}, []string{"operation"})

	RedisLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "lumashield",
		Name:      "redis_operation_latency_seconds",
		Help:      "Redis operation latency",
		Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 12),
	}, []string{"operation"})
)

// RecordAgentStats records stats reported by an agent
func RecordAgentStats(agentID string, packetsProcessed, packetsDropped, bytesProcessed, bytesDropped int64) {
	PacketsProcessed.WithLabelValues(agentID).Add(float64(packetsProcessed))
	PacketsDropped.WithLabelValues(agentID, "rule_match").Add(float64(packetsDropped))
	BytesProcessed.WithLabelValues(agentID).Add(float64(bytesProcessed))
	BytesDropped.WithLabelValues(agentID).Add(float64(bytesDropped))
}

// RecordAPIRequest records an API request
func RecordAPIRequest(method, endpoint, status string, latencySeconds float64) {
	APIRequests.WithLabelValues(method, endpoint, status).Inc()
	APILatency.WithLabelValues(method, endpoint).Observe(latencySeconds)
}

// RecordRuleDistribution records rule distribution latency
func RecordRuleDistribution(latencySeconds float64) {
	RuleDistributionLatency.Observe(latencySeconds)
}

// IncrementActiveAgents increments the active agent count
func IncrementActiveAgents() {
	ActiveAgents.Inc()
	RegisteredAgents.Inc()
}

// DecrementActiveAgents decrements the active agent count
func DecrementActiveAgents() {
	ActiveAgents.Dec()
}

// RecordHeartbeat records a heartbeat from an agent
func RecordHeartbeat(agentID string) {
	AgentHeartbeats.WithLabelValues(agentID).Inc()
}

// UpdateRuleCount updates the total rule count
func UpdateRuleCount(count int) {
	TotalRules.Set(float64(count))
}

// UpdateBlacklistSize updates the blacklist size
func UpdateBlacklistSize(size int) {
	BlacklistSize.Set(float64(size))
}
