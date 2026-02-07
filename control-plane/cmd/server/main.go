package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lumashield/control-plane/internal/api"
	grpcserver "github.com/lumashield/control-plane/internal/grpc"
	"github.com/lumashield/control-plane/internal/redis"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config holds the application configuration
type Config struct {
	// Server settings
	HTTPPort int
	GRPCPort int

	// Redis settings
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// Logging
	LogLevel string
	LogJSON  bool
}

func main() {
	// Load configuration
	cfg := loadConfig()

	// Setup logging
	setupLogging(cfg)

	log.Info().Msg("Starting LumaShield Control Plane")
	log.Info().
		Int("http_port", cfg.HTTPPort).
		Int("grpc_port", cfg.GRPCPort).
		Str("redis_addr", cfg.RedisAddr).
		Msg("Configuration loaded")

	// Connect to Redis
	redisClient, err := redis.NewClient(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Redis")
	}
	defer redisClient.Close()

	// Setup HTTP server
	router := api.SetupRouter(redisClient)
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup gRPC server
	grpcServer := grpcserver.NewServer(redisClient)

	// Channel to receive errors from servers
	errChan := make(chan error, 2)

	// Start HTTP server
	go func() {
		log.Info().Int("port", cfg.HTTPPort).Msg("HTTP server starting")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start gRPC server
	go func() {
		if err := grpcServer.Start(cfg.GRPCPort); err != nil {
			errChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		log.Error().Err(err).Msg("Server error")
	case sig := <-quit:
		log.Info().Str("signal", sig.String()).Msg("Shutdown signal received")
	}

	// Graceful shutdown
	log.Info().Msg("Shutting down servers...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	log.Info().Msg("LumaShield Control Plane stopped")
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	return &Config{
		HTTPPort:      getEnvInt("HTTP_PORT", 8080),
		GRPCPort:      getEnvInt("GRPC_PORT", 50051),
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvInt("REDIS_DB", 0),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		LogJSON:       getEnvBool("LOG_JSON", false),
	}
}

// setupLogging configures zerolog
func setupLogging(cfg *Config) {
	// Set log level
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Configure output
	if cfg.LogJSON {
		// JSON output for production
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
	} else {
		// Console output for development
		log.Logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05",
		}).With().Timestamp().Logger()
	}
}

// Helper functions for environment variables
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intVal int
		if _, err := fmt.Sscanf(value, "%d", &intVal); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}
