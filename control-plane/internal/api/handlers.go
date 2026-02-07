package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lumashield/control-plane/internal/metrics"
	"github.com/lumashield/control-plane/internal/models"
	"github.com/lumashield/control-plane/internal/redis"
	"github.com/rs/zerolog/log"
)

// Handler contains all HTTP handlers
type Handler struct {
	redis *redis.Client
}

// NewHandler creates a new Handler
func NewHandler(redisClient *redis.Client) *Handler {
	return &Handler{
		redis: redisClient,
	}
}

// ============================================================================
// HEALTH ENDPOINTS
// ============================================================================

// HealthCheck returns the health status
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "LumaShield Control Plane is healthy",
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
		},
	})
}

// ReadinessCheck returns the readiness status
func (h *Handler) ReadinessCheck(c *gin.Context) {
	// Check Redis connection
	if err := h.redis.HealthCheck(); err != nil {
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{
			Success: false,
			Error:   "Redis connection failed",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Ready",
	})
}

// ============================================================================
// BLACKLIST ENDPOINTS
// ============================================================================

// GetBlacklist returns all blacklisted IPs
func (h *Handler) GetBlacklist(c *gin.Context) {
	entries, err := h.redis.GetAllBlacklist()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get blacklist")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to retrieve blacklist",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    entries,
	})
}

// AddToBlacklist adds an IP to the blacklist
func (h *Handler) AddToBlacklist(c *gin.Context) {
	var req models.AddToBlacklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request body: " + err.Error(),
		})
		return
	}

	// Check if already blacklisted
	exists, _ := h.redis.IsBlacklisted(req.IP)
	if exists {
		c.JSON(http.StatusConflict, models.APIResponse{
			Success: false,
			Error:   "IP is already blacklisted",
		})
		return
	}

	entry := &models.BlacklistEntry{
		IP:        req.IP,
		Reason:    req.Reason,
		CreatedAt: time.Now(),
		HitCount:  0,
	}

	// Set expiration if TTL provided
	if req.TTL > 0 {
		expiry := time.Now().Add(time.Duration(req.TTL) * time.Second)
		entry.ExpiresAt = &expiry
	}

	if err := h.redis.AddToBlacklist(entry); err != nil {
		log.Error().Err(err).Str("ip", req.IP).Msg("Failed to add to blacklist")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to add to blacklist",
		})
		return
	}

	// Update metrics
	metrics.UpdateBlacklistSize(len(mustGetBlacklist(h.redis)))

	log.Info().Str("ip", req.IP).Str("reason", req.Reason).Msg("IP added to blacklist")

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "IP added to blacklist",
		Data:    entry,
	})
}

// RemoveFromBlacklist removes an IP from the blacklist
func (h *Handler) RemoveFromBlacklist(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "IP parameter is required",
		})
		return
	}

	// Check if exists
	exists, _ := h.redis.IsBlacklisted(ip)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "IP not found in blacklist",
		})
		return
	}

	if err := h.redis.RemoveFromBlacklist(ip); err != nil {
		log.Error().Err(err).Str("ip", ip).Msg("Failed to remove from blacklist")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to remove from blacklist",
		})
		return
	}

	// Update metrics
	metrics.UpdateBlacklistSize(len(mustGetBlacklist(h.redis)))

	log.Info().Str("ip", ip).Msg("IP removed from blacklist")

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "IP removed from blacklist",
	})
}

// CheckBlacklist checks if an IP is blacklisted
func (h *Handler) CheckBlacklist(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "IP parameter is required",
		})
		return
	}

	entry, err := h.redis.GetBlacklistEntry(ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to check blacklist",
		})
		return
	}

	if entry == nil {
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"ip":          ip,
				"blacklisted": false,
			},
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"ip":          ip,
			"blacklisted": true,
			"entry":       entry,
		},
	})
}

// ============================================================================
// RULE ENDPOINTS
// ============================================================================

// GetRules returns all rules
func (h *Handler) GetRules(c *gin.Context) {
	rules, err := h.redis.GetAllRules()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get rules")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to retrieve rules",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    rules,
	})
}

// GetRule returns a single rule by ID
func (h *Handler) GetRule(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Rule ID is required",
		})
		return
	}

	rule, err := h.redis.GetRule(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to retrieve rule",
		})
		return
	}

	if rule == nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    rule,
	})
}

// CreateRule creates a new rule
func (h *Handler) CreateRule(c *gin.Context) {
	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request body: " + err.Error(),
		})
		return
	}

	rule := &models.Rule{
		ID:        uuid.New().String(),
		Type:      req.Type,
		Target:    req.Target,
		Action:    req.Action,
		Reason:    req.Reason,
		Priority:  req.Priority,
		CreatedAt: time.Now(),
		CreatedBy: "api", // TODO: Get from auth context
	}

	// Set expiration if TTL provided
	if req.TTL > 0 {
		expiry := time.Now().Add(time.Duration(req.TTL) * time.Second)
		rule.ExpiresAt = &expiry
	}

	if err := h.redis.SaveRule(rule); err != nil {
		log.Error().Err(err).Msg("Failed to create rule")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to create rule",
		})
		return
	}

	// Update metrics
	metrics.RulesCreated.Inc()
	rules, _ := h.redis.GetAllRules()
	metrics.UpdateRuleCount(len(rules))

	log.Info().Str("id", rule.ID).Str("target", rule.Target).Msg("Rule created")

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Rule created",
		Data:    rule,
	})
}

// DeleteRule deletes a rule
func (h *Handler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Rule ID is required",
		})
		return
	}

	// Check if exists
	rule, _ := h.redis.GetRule(id)
	if rule == nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Rule not found",
		})
		return
	}

	if err := h.redis.DeleteRule(id); err != nil {
		log.Error().Err(err).Str("id", id).Msg("Failed to delete rule")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to delete rule",
		})
		return
	}

	// Update metrics
	metrics.RulesDeleted.Inc()
	rules, _ := h.redis.GetAllRules()
	metrics.UpdateRuleCount(len(rules))

	log.Info().Str("id", id).Msg("Rule deleted")

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Rule deleted",
	})
}

// ============================================================================
// AGENT ENDPOINTS
// ============================================================================

// GetAgents returns all registered agents
func (h *Handler) GetAgents(c *gin.Context) {
	statusFilter := c.Query("status")
	
	agents, err := h.redis.GetAllAgents()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get agents")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to retrieve agents",
		})
		return
	}

	// Filter by status if provided
	if statusFilter != "" {
		filtered := make([]*models.Agent, 0)
		for _, agent := range agents {
			if string(agent.Status) == statusFilter {
				filtered = append(filtered, agent)
			}
		}
		agents = filtered
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    agents,
	})
}

// GetAgent returns a single agent by ID
func (h *Handler) GetAgent(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Agent ID is required",
		})
		return
	}

	agent, err := h.redis.GetAgent(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to retrieve agent",
		})
		return
	}

	if agent == nil {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   "Agent not found",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    agent,
	})
}

// GetAgentStats returns statistics for an agent
func (h *Handler) GetAgentStats(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Agent ID is required",
		})
		return
	}

	// Parse time range
	fromStr := c.DefaultQuery("from", "")
	toStr := c.DefaultQuery("to", "")

	var from, to time.Time
	if fromStr == "" {
		from = time.Now().Add(-1 * time.Hour) // Default: last hour
	} else {
		fromUnix, _ := strconv.ParseInt(fromStr, 10, 64)
		from = time.Unix(fromUnix, 0)
	}
	if toStr == "" {
		to = time.Now()
	} else {
		toUnix, _ := strconv.ParseInt(toStr, 10, 64)
		to = time.Unix(toUnix, 0)
	}

	stats, err := h.redis.GetAgentStats(id, from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to retrieve stats",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    stats,
	})
}

// ============================================================================
// STATS ENDPOINTS
// ============================================================================

// GetSystemStats returns overall system statistics
func (h *Handler) GetSystemStats(c *gin.Context) {
	agents, _ := h.redis.GetAllAgents()
	activeAgents, _ := h.redis.GetActiveAgents()
	rules, _ := h.redis.GetAllRules()
	blacklist, _ := h.redis.GetAllBlacklist()

	stats := models.SystemStats{
		TotalAgents:  len(agents),
		ActiveAgents: len(activeAgents),
		TotalRules:   len(rules),
		Timestamp:    time.Now(),
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"system":         stats,
			"blacklist_size": len(blacklist),
		},
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func mustGetBlacklist(r *redis.Client) []*models.BlacklistEntry {
	entries, _ := r.GetAllBlacklist()
	return entries
}
