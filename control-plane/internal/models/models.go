package models

import (
	"time"
)

// RuleType defines the type of firewall rule
type RuleType string

const (
	RuleTypeIPBlock   RuleType = "ip_block"
	RuleTypeCIDRBlock RuleType = "cidr_block"
	RuleTypeRateLimit RuleType = "rate_limit"
	RuleTypeGeoBlock  RuleType = "geo_block"
	RuleTypePortBlock RuleType = "port_block"
)

// RuleAction defines what action to take when a rule matches
type RuleAction string

const (
	RuleActionDrop      RuleAction = "drop"
	RuleActionReject    RuleAction = "reject"
	RuleActionLog       RuleAction = "log"
	RuleActionRateLimit RuleAction = "rate_limit"
)

// AgentStatus defines the current status of an agent
type AgentStatus string

const (
	AgentStatusActive   AgentStatus = "active"
	AgentStatusInactive AgentStatus = "inactive"
	AgentStatusError    AgentStatus = "error"
)

// Rule represents a firewall rule
type Rule struct {
	ID        string     `json:"id" redis:"id"`
	Type      RuleType   `json:"type" redis:"type"`
	Target    string     `json:"target" redis:"target"`        // IP, CIDR, or pattern
	Action    RuleAction `json:"action" redis:"action"`
	Reason    string     `json:"reason" redis:"reason"`
	Priority  int        `json:"priority" redis:"priority"`    // Higher = more important
	CreatedAt time.Time  `json:"created_at" redis:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" redis:"expires_at"` // nil = never expires
	CreatedBy string     `json:"created_by" redis:"created_by"`
}

// Agent represents a LumaShield agent
type Agent struct {
	ID           string      `json:"id" redis:"id"`
	Hostname     string      `json:"hostname" redis:"hostname"`
	IPAddress    string      `json:"ip_address" redis:"ip_address"`
	Version      string      `json:"version" redis:"version"`
	Status       AgentStatus `json:"status" redis:"status"`
	RegisteredAt time.Time   `json:"registered_at" redis:"registered_at"`
	LastSeenAt   time.Time   `json:"last_seen_at" redis:"last_seen_at"`
	Labels       map[string]string `json:"labels,omitempty" redis:"-"`
}

// AgentStats represents statistics from an agent
type AgentStats struct {
	AgentID           string           `json:"agent_id"`
	PacketsReceived   int64            `json:"packets_received"`
	PacketsPassed     int64            `json:"packets_passed"`
	PacketsDropped    int64            `json:"packets_dropped"`
	BytesReceived     int64            `json:"bytes_received"`
	BytesDropped      int64            `json:"bytes_dropped"`
	ActiveConnections int64            `json:"active_connections"`
	CPUUsage          float64          `json:"cpu_usage"`
	MemoryUsage       float64          `json:"memory_usage"`
	Timestamp         time.Time        `json:"timestamp"`
	DropsByRule       map[string]int64 `json:"drops_by_rule,omitempty"`
}

// BlacklistEntry represents an IP in the blacklist
type BlacklistEntry struct {
	IP        string    `json:"ip" redis:"ip"`
	Reason    string    `json:"reason" redis:"reason"`
	CreatedAt time.Time `json:"created_at" redis:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" redis:"expires_at"`
	HitCount  int64     `json:"hit_count" redis:"hit_count"`
}

// SystemStats represents overall system statistics
type SystemStats struct {
	TotalAgents        int     `json:"total_agents"`
	ActiveAgents       int     `json:"active_agents"`
	TotalRules         int     `json:"total_rules"`
	TotalPacketsDropped int64  `json:"total_packets_dropped"`
	TotalBytesDropped   int64  `json:"total_bytes_dropped"`
	AvgLatencyMs       float64 `json:"avg_latency_ms"`
	Timestamp          time.Time `json:"timestamp"`
}

// CreateRuleRequest represents a request to create a new rule
type CreateRuleRequest struct {
	Type     RuleType   `json:"type" binding:"required"`
	Target   string     `json:"target" binding:"required"`
	Action   RuleAction `json:"action" binding:"required"`
	Reason   string     `json:"reason"`
	Priority int        `json:"priority"`
	TTL      int        `json:"ttl"` // Time to live in seconds, 0 = forever
}

// UpdateRuleRequest represents a request to update a rule
type UpdateRuleRequest struct {
	Action   *RuleAction `json:"action,omitempty"`
	Reason   *string     `json:"reason,omitempty"`
	Priority *int        `json:"priority,omitempty"`
}

// AddToBlacklistRequest represents a request to add an IP to blacklist
type AddToBlacklistRequest struct {
	IP     string `json:"ip" binding:"required"`
	Reason string `json:"reason"`
	TTL    int    `json:"ttl"` // Time to live in seconds, 0 = forever
}

// APIResponse is a generic API response wrapper
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// PaginatedResponse wraps paginated results
type PaginatedResponse struct {
	Items      interface{} `json:"items"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalItems int         `json:"total_items"`
	TotalPages int         `json:"total_pages"`
}
