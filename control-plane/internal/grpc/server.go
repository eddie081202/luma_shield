package grpc

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lumashield/control-plane/internal/metrics"
	"github.com/lumashield/control-plane/internal/models"
	"github.com/lumashield/control-plane/internal/redis"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// AgentConnection represents an active agent connection
type AgentConnection struct {
	AgentID    string
	Stream     grpc.ServerStream
	RuleChan   chan *RuleUpdate
	Connected  time.Time
	LastActive time.Time
}

// RuleUpdate represents a rule update to send to agents
type RuleUpdate struct {
	Type string       // "add", "delete", "modify"
	Rule *models.Rule
}

// Server implements the gRPC ControlPlane service
type Server struct {
	redis       *redis.Client
	connections map[string]*AgentConnection
	connMu      sync.RWMutex
	
	// For broadcasting rules to all agents
	broadcastChan chan *RuleUpdate
}

// NewServer creates a new gRPC server
func NewServer(redisClient *redis.Client) *Server {
	s := &Server{
		redis:         redisClient,
		connections:   make(map[string]*AgentConnection),
		broadcastChan: make(chan *RuleUpdate, 100),
	}

	// Start broadcast worker
	go s.broadcastWorker()

	// Subscribe to Redis rule updates
	redisClient.SubscribeRuleUpdates(func(msg *redis.RuleUpdateMessage) {
		s.broadcastChan <- &RuleUpdate{
			Type: msg.Type,
			Rule: msg.Rule,
		}
	})

	return s
}

// Start starts the gRPC server
func (s *Server) Start(port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// gRPC server options
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  5 * time.Minute,
			Timeout:               1 * time.Minute,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	grpcServer := grpc.NewServer(opts...)
	
	// Register our server
	RegisterControlPlaneServer(grpcServer, s)

	log.Info().Int("port", port).Msg("gRPC server starting")
	return grpcServer.Serve(lis)
}

// ============================================================================
// GRPC SERVICE IMPLEMENTATION
// ============================================================================

// Register handles agent registration
func (s *Server) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	if req.Agent == nil {
		return nil, status.Error(codes.InvalidArgument, "agent is required")
	}

	agent := &models.Agent{
		ID:           req.Agent.Id,
		Hostname:     req.Agent.Hostname,
		IPAddress:    req.Agent.IpAddress,
		Version:      req.Agent.Version,
		Status:       models.AgentStatusActive,
		RegisteredAt: time.Now(),
		LastSeenAt:   time.Now(),
	}

	// Generate ID if not provided
	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}

	// Save to Redis
	if err := s.redis.RegisterAgent(agent); err != nil {
		log.Error().Err(err).Str("agent_id", agent.ID).Msg("Failed to register agent")
		return nil, status.Error(codes.Internal, "failed to register agent")
	}

	// Get current rules to send to agent
	rules, err := s.redis.GetAllRules()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get rules for agent")
	}

	// Convert rules to proto format
	protoRules := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		protoRules = append(protoRules, modelRuleToProto(r))
	}

	// Update metrics
	metrics.IncrementActiveAgents()

	log.Info().
		Str("agent_id", agent.ID).
		Str("hostname", agent.Hostname).
		Str("ip", agent.IPAddress).
		Msg("Agent registered")

	return &RegisterResponse{
		Success:            true,
		Message:            "Registration successful",
		InitialRules:       protoRules,
		HeartbeatIntervalMs: 30000, // 30 seconds
	}, nil
}

// Heartbeat handles agent heartbeats
func (s *Server) Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	if req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}

	// Update agent status in Redis
	agentStatus := models.AgentStatusActive
	if req.Status == AgentStatus_AGENT_STATUS_ERROR {
		agentStatus = models.AgentStatusError
	}

	if err := s.redis.UpdateAgentStatus(req.AgentId, agentStatus); err != nil {
		log.Warn().Err(err).Str("agent_id", req.AgentId).Msg("Failed to update agent status")
	}

	// Update connection last active time
	s.connMu.Lock()
	if conn, ok := s.connections[req.AgentId]; ok {
		conn.LastActive = time.Now()
	}
	s.connMu.Unlock()

	// Record metrics
	metrics.RecordHeartbeat(req.AgentId)

	return &HeartbeatResponse{
		Acknowledged:    true,
		ShouldReconnect: false,
	}, nil
}

// StreamRules implements bidirectional streaming for rule updates
func (s *Server) StreamRules(stream ControlPlane_StreamRulesServer) error {
	// First message should identify the agent
	firstMsg, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "failed to receive initial message")
	}

	agentID := firstMsg.Stats.AgentId
	if agentID == "" {
		return status.Error(codes.InvalidArgument, "agent_id is required in first message")
	}

	log.Info().Str("agent_id", agentID).Msg("Agent connected to rule stream")

	// Create connection entry
	conn := &AgentConnection{
		AgentID:    agentID,
		RuleChan:   make(chan *RuleUpdate, 100),
		Connected:  time.Now(),
		LastActive: time.Now(),
	}

	s.connMu.Lock()
	s.connections[agentID] = conn
	s.connMu.Unlock()

	// Update metrics
	metrics.GRPCConnections.Inc()

	// Cleanup on disconnect
	defer func() {
		s.connMu.Lock()
		delete(s.connections, agentID)
		s.connMu.Unlock()
		close(conn.RuleChan)
		metrics.GRPCConnections.Dec()
		metrics.DecrementActiveAgents()
		
		// Mark agent as inactive
		s.redis.UpdateAgentStatus(agentID, models.AgentStatusInactive)
		
		log.Info().Str("agent_id", agentID).Msg("Agent disconnected from rule stream")
	}()

	// Process the first stats message
	s.processStats(firstMsg.Stats)

	// Create error channel
	errChan := make(chan error, 2)

	// Goroutine to receive stats from agent
	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				errChan <- nil
				return
			}
			if err != nil {
				errChan <- err
				return
			}

			conn.LastActive = time.Now()
			s.processStats(msg.Stats)
			metrics.GRPCStreamMessages.WithLabelValues("recv", "stats").Inc()
		}
	}()

	// Goroutine to send rule updates to agent
	go func() {
		for update := range conn.RuleChan {
			protoUpdate := &RuleUpdate_Proto{
				Type: stringToUpdateType(update.Type),
				Rule: modelRuleToProto(update.Rule),
			}

			if err := stream.Send(protoUpdate); err != nil {
				errChan <- err
				return
			}
			metrics.GRPCStreamMessages.WithLabelValues("send", "rule_update").Inc()
		}
	}()

	// Wait for error or disconnect
	return <-errChan
}

// StreamCommands implements command streaming to agents
func (s *Server) StreamCommands(stream ControlPlane_StreamCommandsServer) error {
	// Similar implementation to StreamRules
	// For now, just keep the connection alive
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ============================================================================
// HELPER METHODS
// ============================================================================

// processStats processes stats reported by an agent
func (s *Server) processStats(stats *AgentStats) {
	if stats == nil {
		return
	}

	// Convert to model
	modelStats := &models.AgentStats{
		AgentID:           stats.AgentId,
		PacketsReceived:   stats.PacketsReceived,
		PacketsPassed:     stats.PacketsPassed,
		PacketsDropped:    stats.PacketsDropped,
		BytesReceived:     stats.BytesReceived,
		BytesDropped:      stats.BytesDropped,
		ActiveConnections: stats.ActiveConnections,
		CPUUsage:          stats.CpuUsage,
		MemoryUsage:       stats.MemoryUsage,
		Timestamp:         time.Now(),
		DropsByRule:       stats.DropsByRule,
	}

	// Save to Redis
	if err := s.redis.SaveAgentStats(modelStats); err != nil {
		log.Warn().Err(err).Str("agent_id", stats.AgentId).Msg("Failed to save agent stats")
	}

	// Update Prometheus metrics
	metrics.RecordAgentStats(
		stats.AgentId,
		stats.PacketsReceived,
		stats.PacketsDropped,
		stats.BytesReceived,
		stats.BytesDropped,
	)

	log.Debug().
		Str("agent_id", stats.AgentId).
		Int64("packets_processed", stats.PacketsReceived).
		Int64("packets_dropped", stats.PacketsDropped).
		Msg("Received agent stats")
}

// broadcastWorker sends rule updates to all connected agents
func (s *Server) broadcastWorker() {
	for update := range s.broadcastChan {
		start := time.Now()

		s.connMu.RLock()
		for agentID, conn := range s.connections {
			select {
			case conn.RuleChan <- update:
				// Sent successfully
			default:
				log.Warn().Str("agent_id", agentID).Msg("Rule channel full, skipping")
			}
		}
		agentCount := len(s.connections)
		s.connMu.RUnlock()

		latency := time.Since(start).Seconds()
		metrics.RecordRuleDistribution(latency)

		log.Info().
			Str("rule_id", update.Rule.ID).
			Str("type", update.Type).
			Int("agents", agentCount).
			Float64("latency_ms", latency*1000).
			Msg("Rule broadcasted to agents")
	}
}

// BroadcastRule sends a rule update to all connected agents
func (s *Server) BroadcastRule(updateType string, rule *models.Rule) {
	s.broadcastChan <- &RuleUpdate{
		Type: updateType,
		Rule: rule,
	}
}

// GetConnectedAgents returns the number of connected agents
func (s *Server) GetConnectedAgents() int {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return len(s.connections)
}

// ============================================================================
// CONVERSION HELPERS
// ============================================================================

func modelRuleToProto(r *models.Rule) *Rule {
	if r == nil {
		return nil
	}

	rule := &Rule{
		Id:        r.ID,
		Type:      ruleTypeToProto(r.Type),
		Target:    r.Target,
		Action:    ruleActionToProto(r.Action),
		Reason:    r.Reason,
		Priority:  int32(r.Priority),
		CreatedAt: r.CreatedAt.Unix(),
	}

	if r.ExpiresAt != nil {
		rule.ExpiresAt = r.ExpiresAt.Unix()
	}

	return rule
}

func ruleTypeToProto(t models.RuleType) RuleType {
	switch t {
	case models.RuleTypeIPBlock:
		return RuleType_RULE_TYPE_IP_BLOCK
	case models.RuleTypeCIDRBlock:
		return RuleType_RULE_TYPE_CIDR_BLOCK
	case models.RuleTypeRateLimit:
		return RuleType_RULE_TYPE_RATE_LIMIT
	case models.RuleTypeGeoBlock:
		return RuleType_RULE_TYPE_GEO_BLOCK
	case models.RuleTypePortBlock:
		return RuleType_RULE_TYPE_PORT_BLOCK
	default:
		return RuleType_RULE_TYPE_UNKNOWN
	}
}

func ruleActionToProto(a models.RuleAction) RuleAction {
	switch a {
	case models.RuleActionDrop:
		return RuleAction_RULE_ACTION_DROP
	case models.RuleActionReject:
		return RuleAction_RULE_ACTION_REJECT
	case models.RuleActionLog:
		return RuleAction_RULE_ACTION_LOG
	case models.RuleActionRateLimit:
		return RuleAction_RULE_ACTION_RATE_LIMIT
	default:
		return RuleAction_RULE_ACTION_UNKNOWN
	}
}

func stringToUpdateType(s string) UpdateType {
	switch s {
	case "add":
		return UpdateType_UPDATE_TYPE_ADD
	case "delete":
		return UpdateType_UPDATE_TYPE_REMOVE
	case "modify":
		return UpdateType_UPDATE_TYPE_MODIFY
	default:
		return UpdateType_UPDATE_TYPE_UNKNOWN
	}
}

// ============================================================================
// PROTO TYPE ALIASES (these would normally be generated from proto)
// ============================================================================

// These are placeholder types - in a real project, these would be generated
// by protoc from the .proto file

type RegisterRequest struct {
	Agent *Agent
}

type Agent struct {
	Id        string
	Hostname  string
	IpAddress string
	Version   string
}

type RegisterResponse struct {
	Success             bool
	Message             string
	InitialRules        []*Rule
	HeartbeatIntervalMs int64
}

type HeartbeatRequest struct {
	AgentId string
	Status  AgentStatus
}

type HeartbeatResponse struct {
	Acknowledged    bool
	ShouldReconnect bool
}

type AgentStatus int32

const (
	AgentStatus_AGENT_STATUS_UNKNOWN  AgentStatus = 0
	AgentStatus_AGENT_STATUS_ACTIVE   AgentStatus = 1
	AgentStatus_AGENT_STATUS_INACTIVE AgentStatus = 2
	AgentStatus_AGENT_STATUS_ERROR    AgentStatus = 3
)

type Rule struct {
	Id        string
	Type      RuleType
	Target    string
	Action    RuleAction
	Reason    string
	Priority  int32
	CreatedAt int64
	ExpiresAt int64
}

type RuleType int32

const (
	RuleType_RULE_TYPE_UNKNOWN    RuleType = 0
	RuleType_RULE_TYPE_IP_BLOCK   RuleType = 1
	RuleType_RULE_TYPE_CIDR_BLOCK RuleType = 2
	RuleType_RULE_TYPE_RATE_LIMIT RuleType = 3
	RuleType_RULE_TYPE_GEO_BLOCK  RuleType = 4
	RuleType_RULE_TYPE_PORT_BLOCK RuleType = 5
)

type RuleAction int32

const (
	RuleAction_RULE_ACTION_UNKNOWN    RuleAction = 0
	RuleAction_RULE_ACTION_DROP       RuleAction = 1
	RuleAction_RULE_ACTION_REJECT     RuleAction = 2
	RuleAction_RULE_ACTION_LOG        RuleAction = 3
	RuleAction_RULE_ACTION_RATE_LIMIT RuleAction = 4
)

type UpdateType int32

const (
	UpdateType_UPDATE_TYPE_UNKNOWN UpdateType = 0
	UpdateType_UPDATE_TYPE_ADD     UpdateType = 1
	UpdateType_UPDATE_TYPE_REMOVE  UpdateType = 2
	UpdateType_UPDATE_TYPE_MODIFY  UpdateType = 3
)

type AgentStats struct {
	AgentId           string
	PacketsReceived   int64
	PacketsPassed     int64
	PacketsDropped    int64
	BytesReceived     int64
	BytesDropped      int64
	ActiveConnections int64
	CpuUsage          float64
	MemoryUsage       float64
	Timestamp         int64
	DropsByRule       map[string]int64
}

type StatsReport struct {
	Stats *AgentStats
}

type RuleUpdate_Proto struct {
	Type UpdateType
	Rule *Rule
}

type AgentCommand struct {
	Type       CommandType
	Parameters map[string]string
}

type CommandType int32

// Server interface stubs (would be generated by protoc)
type ControlPlane_StreamRulesServer interface {
	Send(*RuleUpdate_Proto) error
	Recv() (*StatsReport, error)
	grpc.ServerStream
}

type ControlPlane_StreamCommandsServer interface {
	Send(*AgentCommand) error
	Recv() (*HeartbeatRequest, error)
	grpc.ServerStream
}

// RegisterControlPlaneServer registers the server (stub)
func RegisterControlPlaneServer(s *grpc.Server, srv *Server) {
	// In a real implementation, this would be generated by protoc
	// For now, we'll just log that it was called
	log.Info().Msg("Registered ControlPlane gRPC server")
}
