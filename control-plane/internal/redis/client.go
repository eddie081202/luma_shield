package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lumashield/control-plane/internal/models"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	// Redis key prefixes
	keyPrefixBlacklist = "blacklist"
	keyPrefixRules     = "rules"
	keyPrefixAgents    = "agents"
	keyPrefixStats     = "stats"
	
	// Pub/Sub channels
	channelRuleUpdates = "rule_updates"
	channelAgentEvents = "agent_events"
)

// Client wraps Redis operations for LumaShield
type Client struct {
	rdb *redis.Client
	ctx context.Context
}

// NewClient creates a new Redis client
func NewClient(addr string, password string, db int) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
		PoolSize: 100,
	})

	ctx := context.Background()
	
	// Test connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Info().Str("addr", addr).Msg("Connected to Redis")

	return &Client{
		rdb: rdb,
		ctx: ctx,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.rdb.Close()
}

// ============================================================================
// BLACKLIST OPERATIONS
// ============================================================================

// AddToBlacklist adds an IP to the blacklist
func (c *Client) AddToBlacklist(entry *models.BlacklistEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal blacklist entry: %w", err)
	}

	key := fmt.Sprintf("%s:%s", keyPrefixBlacklist, entry.IP)
	
	// Set with optional TTL
	if entry.ExpiresAt != nil {
		ttl := time.Until(*entry.ExpiresAt)
		if ttl > 0 {
			return c.rdb.Set(c.ctx, key, data, ttl).Err()
		}
	}
	
	return c.rdb.Set(c.ctx, key, data, 0).Err()
}

// RemoveFromBlacklist removes an IP from the blacklist
func (c *Client) RemoveFromBlacklist(ip string) error {
	key := fmt.Sprintf("%s:%s", keyPrefixBlacklist, ip)
	return c.rdb.Del(c.ctx, key).Err()
}

// IsBlacklisted checks if an IP is in the blacklist
func (c *Client) IsBlacklisted(ip string) (bool, error) {
	key := fmt.Sprintf("%s:%s", keyPrefixBlacklist, ip)
	exists, err := c.rdb.Exists(c.ctx, key).Result()
	return exists > 0, err
}

// GetBlacklistEntry retrieves a blacklist entry
func (c *Client) GetBlacklistEntry(ip string) (*models.BlacklistEntry, error) {
	key := fmt.Sprintf("%s:%s", keyPrefixBlacklist, ip)
	data, err := c.rdb.Get(c.ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var entry models.BlacklistEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// GetAllBlacklist retrieves all blacklisted IPs
func (c *Client) GetAllBlacklist() ([]*models.BlacklistEntry, error) {
	pattern := fmt.Sprintf("%s:*", keyPrefixBlacklist)
	keys, err := c.rdb.Keys(c.ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	entries := make([]*models.BlacklistEntry, 0, len(keys))
	for _, key := range keys {
		data, err := c.rdb.Get(c.ctx, key).Result()
		if err != nil {
			continue
		}
		
		var entry models.BlacklistEntry
		if err := json.Unmarshal([]byte(data), &entry); err != nil {
			continue
		}
		entries = append(entries, &entry)
	}

	return entries, nil
}

// IncrementBlacklistHit increments the hit count for a blacklisted IP
func (c *Client) IncrementBlacklistHit(ip string) error {
	entry, err := c.GetBlacklistEntry(ip)
	if err != nil || entry == nil {
		return err
	}
	
	entry.HitCount++
	return c.AddToBlacklist(entry)
}

// ============================================================================
// RULE OPERATIONS
// ============================================================================

// SaveRule saves a rule to Redis
func (c *Client) SaveRule(rule *models.Rule) error {
	data, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}

	key := fmt.Sprintf("%s:%s", keyPrefixRules, rule.ID)
	
	// Set with optional TTL
	if rule.ExpiresAt != nil {
		ttl := time.Until(*rule.ExpiresAt)
		if ttl > 0 {
			if err := c.rdb.Set(c.ctx, key, data, ttl).Err(); err != nil {
				return err
			}
		}
	} else {
		if err := c.rdb.Set(c.ctx, key, data, 0).Err(); err != nil {
			return err
		}
	}

	// Also add to sorted set for ordering by priority
	c.rdb.ZAdd(c.ctx, keyPrefixRules, redis.Z{
		Score:  float64(rule.Priority),
		Member: rule.ID,
	})

	// Publish update
	c.PublishRuleUpdate("add", rule)

	return nil
}

// GetRule retrieves a rule by ID
func (c *Client) GetRule(id string) (*models.Rule, error) {
	key := fmt.Sprintf("%s:%s", keyPrefixRules, id)
	data, err := c.rdb.Get(c.ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var rule models.Rule
	if err := json.Unmarshal([]byte(data), &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// DeleteRule deletes a rule
func (c *Client) DeleteRule(id string) error {
	rule, err := c.GetRule(id)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s:%s", keyPrefixRules, id)
	if err := c.rdb.Del(c.ctx, key).Err(); err != nil {
		return err
	}

	// Remove from sorted set
	c.rdb.ZRem(c.ctx, keyPrefixRules, id)

	// Publish delete
	if rule != nil {
		c.PublishRuleUpdate("delete", rule)
	}

	return nil
}

// GetAllRules retrieves all rules, ordered by priority
func (c *Client) GetAllRules() ([]*models.Rule, error) {
	// Get IDs ordered by priority (descending)
	ids, err := c.rdb.ZRevRange(c.ctx, keyPrefixRules, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	rules := make([]*models.Rule, 0, len(ids))
	for _, id := range ids {
		rule, err := c.GetRule(id)
		if err != nil || rule == nil {
			continue
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// ============================================================================
// AGENT OPERATIONS
// ============================================================================

// RegisterAgent registers or updates an agent
func (c *Client) RegisterAgent(agent *models.Agent) error {
	data, err := json.Marshal(agent)
	if err != nil {
		return fmt.Errorf("failed to marshal agent: %w", err)
	}

	key := fmt.Sprintf("%s:%s", keyPrefixAgents, agent.ID)
	return c.rdb.Set(c.ctx, key, data, 0).Err()
}

// GetAgent retrieves an agent by ID
func (c *Client) GetAgent(id string) (*models.Agent, error) {
	key := fmt.Sprintf("%s:%s", keyPrefixAgents, id)
	data, err := c.rdb.Get(c.ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var agent models.Agent
	if err := json.Unmarshal([]byte(data), &agent); err != nil {
		return nil, err
	}
	return &agent, nil
}

// UpdateAgentStatus updates an agent's status and last seen time
func (c *Client) UpdateAgentStatus(id string, status models.AgentStatus) error {
	agent, err := c.GetAgent(id)
	if err != nil || agent == nil {
		return fmt.Errorf("agent not found: %s", id)
	}

	agent.Status = status
	agent.LastSeenAt = time.Now()
	return c.RegisterAgent(agent)
}

// GetAllAgents retrieves all registered agents
func (c *Client) GetAllAgents() ([]*models.Agent, error) {
	pattern := fmt.Sprintf("%s:*", keyPrefixAgents)
	keys, err := c.rdb.Keys(c.ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	agents := make([]*models.Agent, 0, len(keys))
	for _, key := range keys {
		data, err := c.rdb.Get(c.ctx, key).Result()
		if err != nil {
			continue
		}
		
		var agent models.Agent
		if err := json.Unmarshal([]byte(data), &agent); err != nil {
			continue
		}
		agents = append(agents, &agent)
	}

	return agents, nil
}

// GetActiveAgents returns only active agents
func (c *Client) GetActiveAgents() ([]*models.Agent, error) {
	allAgents, err := c.GetAllAgents()
	if err != nil {
		return nil, err
	}

	active := make([]*models.Agent, 0)
	for _, agent := range allAgents {
		if agent.Status == models.AgentStatusActive {
			active = append(active, agent)
		}
	}
	return active, nil
}

// ============================================================================
// STATS OPERATIONS
// ============================================================================

// SaveAgentStats saves agent statistics
func (c *Client) SaveAgentStats(stats *models.AgentStats) error {
	data, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("failed to marshal stats: %w", err)
	}

	// Use timestamp-based key for time-series data
	key := fmt.Sprintf("%s:%s:%d", keyPrefixStats, stats.AgentID, stats.Timestamp.Unix())
	
	// Auto-expire after 24 hours
	return c.rdb.Set(c.ctx, key, data, 24*time.Hour).Err()
}

// GetAgentStats retrieves stats for an agent within a time range
func (c *Client) GetAgentStats(agentID string, from, to time.Time) ([]*models.AgentStats, error) {
	pattern := fmt.Sprintf("%s:%s:*", keyPrefixStats, agentID)
	keys, err := c.rdb.Keys(c.ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	stats := make([]*models.AgentStats, 0)
	for _, key := range keys {
		data, err := c.rdb.Get(c.ctx, key).Result()
		if err != nil {
			continue
		}
		
		var stat models.AgentStats
		if err := json.Unmarshal([]byte(data), &stat); err != nil {
			continue
		}
		
		// Filter by time range
		if stat.Timestamp.After(from) && stat.Timestamp.Before(to) {
			stats = append(stats, &stat)
		}
	}

	return stats, nil
}

// ============================================================================
// PUB/SUB OPERATIONS
// ============================================================================

// RuleUpdateMessage represents a rule update message
type RuleUpdateMessage struct {
	Type string       `json:"type"` // "add", "delete", "modify"
	Rule *models.Rule `json:"rule"`
}

// PublishRuleUpdate publishes a rule update to all subscribers
func (c *Client) PublishRuleUpdate(updateType string, rule *models.Rule) error {
	msg := RuleUpdateMessage{
		Type: updateType,
		Rule: rule,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.rdb.Publish(c.ctx, channelRuleUpdates, data).Err()
}

// SubscribeRuleUpdates subscribes to rule updates
func (c *Client) SubscribeRuleUpdates(handler func(*RuleUpdateMessage)) {
	sub := c.rdb.Subscribe(c.ctx, channelRuleUpdates)
	ch := sub.Channel()

	go func() {
		for msg := range ch {
			var update RuleUpdateMessage
			if err := json.Unmarshal([]byte(msg.Payload), &update); err != nil {
				log.Error().Err(err).Msg("Failed to unmarshal rule update")
				continue
			}
			handler(&update)
		}
	}()
}

// ============================================================================
// UTILITY OPERATIONS
// ============================================================================

// GetStats returns Redis statistics
func (c *Client) GetStats() map[string]interface{} {
	info, _ := c.rdb.Info(c.ctx, "stats").Result()
	return map[string]interface{}{
		"info": info,
	}
}

// HealthCheck performs a health check
func (c *Client) HealthCheck() error {
	return c.rdb.Ping(c.ctx).Err()
}
