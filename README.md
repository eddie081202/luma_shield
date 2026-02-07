# 🛡️ LUMA SHIELD

**Distributed High-Performance Security & Traffic Gateway**

A cloud-native firewall and traffic optimization system inspired by Cloudflare and Cilium.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LUMA SHIELD ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     SaaS Platform (Layer 3)                          │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│   │  │  Dashboard  │  │  Prometheus │  │   Grafana   │                  │   │
│   │  │   (React)   │  │   Metrics   │  │  Dashboards │                  │   │
│   │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    Control Plane (Layer 2) - Go                      │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│   │  │  REST API   │  │    gRPC     │  │    Redis    │                  │   │
│   │  │   :8080     │  │   :50051    │  │  Blacklist  │                  │   │
│   │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                    gRPC Bidirectional Streaming                             │
│                                    │                                         │
│   ┌────────────────┬───────────────┼───────────────┬────────────────┐       │
│   │                │               │               │                │       │
│   ▼                ▼               ▼               ▼                ▼       │
│ ┌──────┐       ┌──────┐       ┌──────┐       ┌──────┐       ┌──────┐       │
│ │Agent │       │Agent │       │Agent │       │Agent │       │Agent │       │
│ │ XDP  │       │ XDP  │       │ XDP  │       │ XDP  │       │ XDP  │       │
│ └──────┘       └──────┘       └──────┘       └──────┘       └──────┘       │
│   │                │               │               │                │       │
│   ▼                ▼               ▼               ▼                ▼       │
│ [NIC]            [NIC]           [NIC]           [NIC]            [NIC]     │
│                                                                              │
│                     Data Plane (Layer 1) - C++/eBPF                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Data Plane (C++/eBPF)
- **XDP Agent**: Ultra-fast packet processing at kernel level
- **eBPF Programs**: Firewall rules executed in kernel space
- **Performance**: Drop DDoS packets before they reach the OS

### 2. Control Plane (Go)
- **REST API**: Management interface for rules and configuration
- **gRPC Server**: Real-time bidirectional streaming with agents
- **Redis**: Fast blacklist storage and pub/sub for rule distribution

### 3. SaaS Platform (Kubernetes)
- **Helm Charts**: One-command deployment
- **Prometheus**: Metrics collection
- **Grafana**: Real-time dashboards

## Quick Start

### Prerequisites
- Go 1.21+
- Docker & Docker Compose
- Linux (for XDP agent) or WSL2

### Local Development

```bash
# Start all services
docker-compose up -d

# Control Plane API available at http://localhost:8080
# Grafana dashboard at http://localhost:3000 (admin/admin)
```

### API Examples

```bash
# Add IP to blacklist
curl -X POST http://localhost:8080/api/v1/blacklist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "DDoS attack"}'

# Get all blocked IPs
curl http://localhost:8080/api/v1/blacklist

# Get agent status
curl http://localhost:8080/api/v1/agents

# Get statistics
curl http://localhost:8080/api/v1/stats
```

## Project Structure

```
lumashield/
├── agent/                      # C++ XDP Agent
│   ├── src/
│   │   ├── bpf/               # eBPF/XDP programs
│   │   └── grpc/              # gRPC client
│   ├── include/
│   └── CMakeLists.txt
│
├── control-plane/              # Go Backend
│   ├── cmd/server/            # Main entry point
│   ├── internal/
│   │   ├── api/               # REST handlers
│   │   ├── grpc/              # gRPC server
│   │   ├── redis/             # Redis client
│   │   ├── metrics/           # Prometheus metrics
│   │   └── models/            # Data models
│   └── proto/                 # Protobuf definitions
│
├── helm/lumashield/           # Helm chart
├── k8s/                       # Raw Kubernetes manifests
├── monitoring/                # Prometheus & Grafana configs
├── scripts/                   # Utility scripts
└── docker-compose.yml
```

## Performance

| Metric | Value |
|--------|-------|
| Packet processing | ~10M pps per agent |
| Rule distribution latency | < 1ms globally |
| Blacklist lookup | O(1) via eBPF hash maps |

## License

MIT License
