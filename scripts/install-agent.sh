#!/bin/bash
# LumaShield Agent Installation Script
# Usage: curl -sSL https://get.lumashield.io/agent | bash -s -- --server <control-plane-address>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
CONTROL_PLANE=""
INTERFACE="eth0"
INSTALL_DIR="/opt/lumashield"
BPF_DIR="/usr/share/lumashield/bpf"
CONFIG_DIR="/etc/lumashield"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server|-s)
            CONTROL_PLANE="$2"
            shift 2
            ;;
        --interface|-i)
            INTERFACE="$2"
            shift 2
            ;;
        --help|-h)
            echo "LumaShield Agent Installer"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --server, -s <addr>     Control Plane address (required)"
            echo "  --interface, -i <name>  Network interface (default: eth0)"
            echo "  --help, -h              Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check requirements
check_requirements() {
    echo -e "${YELLOW}Checking requirements...${NC}"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: Please run as root${NC}"
        exit 1
    fi
    
    # Check kernel version (need 5.x+ for modern BPF)
    KERNEL_VERSION=$(uname -r | cut -d. -f1)
    if [ "$KERNEL_VERSION" -lt 5 ]; then
        echo -e "${RED}Error: Kernel 5.x or higher required (found: $(uname -r))${NC}"
        exit 1
    fi
    
    # Check if Control Plane address provided
    if [ -z "$CONTROL_PLANE" ]; then
        echo -e "${RED}Error: Control Plane address required (--server)${NC}"
        exit 1
    fi
    
    # Check if interface exists
    if ! ip link show "$INTERFACE" &> /dev/null; then
        echo -e "${RED}Error: Interface $INTERFACE not found${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Requirements check passed${NC}"
}

# Install dependencies
install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y libbpf1 libelf1 zlib1g curl
    elif command -v yum &> /dev/null; then
        yum install -y libbpf elfutils-libelf zlib curl
    elif command -v dnf &> /dev/null; then
        dnf install -y libbpf elfutils-libelf zlib curl
    else
        echo -e "${RED}Error: Unsupported package manager${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Dependencies installed${NC}"
}

# Download and install agent
install_agent() {
    echo -e "${YELLOW}Installing LumaShield Agent...${NC}"
    
    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BPF_DIR"
    mkdir -p "$CONFIG_DIR"
    
    # Download agent binary
    echo "Downloading agent binary..."
    curl -sSL "https://releases.lumashield.io/agent/latest/lumashield-agent-linux-amd64" \
        -o "$INSTALL_DIR/lumashield-agent"
    chmod +x "$INSTALL_DIR/lumashield-agent"
    
    # Download BPF programs
    echo "Downloading BPF programs..."
    curl -sSL "https://releases.lumashield.io/agent/latest/firewall.bpf.o" \
        -o "$BPF_DIR/firewall.bpf.o"
    curl -sSL "https://releases.lumashield.io/agent/latest/stats.bpf.o" \
        -o "$BPF_DIR/stats.bpf.o"
    
    # Create configuration
    cat > "$CONFIG_DIR/agent.conf" << EOF
# LumaShield Agent Configuration
control_plane_addr = $CONTROL_PLANE
interface = $INTERFACE
bpf_object_path = $BPF_DIR/firewall.bpf.o
log_level = info
EOF
    
    # Create symlink
    ln -sf "$INSTALL_DIR/lumashield-agent" /usr/local/bin/lumashield-agent
    
    echo -e "${GREEN}Agent installed${NC}"
}

# Create systemd service
create_service() {
    echo -e "${YELLOW}Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/lumashield-agent.service << EOF
[Unit]
Description=LumaShield Security Agent
Documentation=https://docs.lumashield.io
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/lumashield-agent -c $CONFIG_DIR/agent.conf
Restart=always
RestartSec=5
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Security settings
NoNewPrivileges=no
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable lumashield-agent
    
    echo -e "${GREEN}Service created${NC}"
}

# Start agent
start_agent() {
    echo -e "${YELLOW}Starting LumaShield Agent...${NC}"
    
    systemctl start lumashield-agent
    
    # Wait for startup
    sleep 2
    
    if systemctl is-active --quiet lumashield-agent; then
        echo -e "${GREEN}LumaShield Agent started successfully!${NC}"
        echo ""
        echo "Agent ID: $(journalctl -u lumashield-agent -n 20 | grep -oP 'Agent started successfully with ID: \K[^ ]+')"
        echo "Control Plane: $CONTROL_PLANE"
        echo "Interface: $INTERFACE"
        echo ""
        echo "Commands:"
        echo "  Status:   systemctl status lumashield-agent"
        echo "  Logs:     journalctl -u lumashield-agent -f"
        echo "  Restart:  systemctl restart lumashield-agent"
        echo "  Stop:     systemctl stop lumashield-agent"
    else
        echo -e "${RED}Failed to start agent. Check logs: journalctl -u lumashield-agent${NC}"
        exit 1
    fi
}

# Main installation flow
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           LumaShield Agent Installer v1.0.0               ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    
    check_requirements
    install_dependencies
    install_agent
    create_service
    start_agent
    
    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
}

main
