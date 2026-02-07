package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lumashield/control-plane/internal/metrics"
	"github.com/lumashield/control-plane/internal/redis"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SetupRouter creates and configures the Gin router
func SetupRouter(redisClient *redis.Client) *gin.Engine {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(loggingMiddleware())
	router.Use(corsMiddleware())
	router.Use(metricsMiddleware())

	// Create handler
	h := NewHandler(redisClient)

	// Health endpoints (no auth required)
	router.GET("/health", h.HealthCheck)
	router.GET("/ready", h.ReadinessCheck)

	// Prometheus metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Blacklist management
		blacklist := v1.Group("/blacklist")
		{
			blacklist.GET("", h.GetBlacklist)
			blacklist.POST("", h.AddToBlacklist)
			blacklist.GET("/:ip", h.CheckBlacklist)
			blacklist.DELETE("/:ip", h.RemoveFromBlacklist)
		}

		// Rule management
		rules := v1.Group("/rules")
		{
			rules.GET("", h.GetRules)
			rules.POST("", h.CreateRule)
			rules.GET("/:id", h.GetRule)
			rules.DELETE("/:id", h.DeleteRule)
		}

		// Agent management
		agents := v1.Group("/agents")
		{
			agents.GET("", h.GetAgents)
			agents.GET("/:id", h.GetAgent)
			agents.GET("/:id/stats", h.GetAgentStats)
		}

		// System stats
		v1.GET("/stats", h.GetSystemStats)
	}

	return router
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/health", "/ready", "/metrics"},
	})
}

// corsMiddleware handles CORS
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// metricsMiddleware records request metrics
func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// Skip health/metrics endpoints
		path := c.FullPath()
		if path == "/health" || path == "/ready" || path == "/metrics" {
			return
		}

		latency := time.Since(start).Seconds()
		status := c.Writer.Status()

		metrics.RecordAPIRequest(
			c.Request.Method,
			path,
			statusToString(status),
			latency,
		)
	}
}

func statusToString(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "other"
	}
}
