# LumaShield Agent Dockerfile
# Requires Linux with BPF support

# ============================================================================
# Stage 1: Build BPF Programs
# ============================================================================
FROM ubuntu:22.04 AS bpf-builder

# Install BPF build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy BPF source files
COPY src/bpf/ /app/src/bpf/

# Compile BPF programs
RUN clang -g -O2 -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c /app/src/bpf/firewall.bpf.c \
    -o /app/firewall.bpf.o

RUN clang -g -O2 -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c /app/src/bpf/stats.bpf.c \
    -o /app/stats.bpf.o

# Strip debug info for smaller size
RUN llvm-strip -g /app/firewall.bpf.o /app/stats.bpf.o

# ============================================================================
# Stage 2: Build C++ Agent
# ============================================================================
FROM ubuntu:22.04 AS cpp-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    libgrpc++-dev \
    libprotobuf-dev \
    protobuf-compiler-grpc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source files
COPY CMakeLists.txt /app/
COPY include/ /app/include/
COPY src/ /app/src/

# Build agent
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_BPF=OFF .. && \
    make -j$(nproc)

# ============================================================================
# Stage 3: Runtime
# ============================================================================
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libbpf1 \
    libelf1 \
    zlib1g \
    libgrpc++1 \
    libprotobuf23 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /usr/share/lumashield/bpf /etc/lumashield

# Copy BPF programs from builder
COPY --from=bpf-builder /app/*.bpf.o /usr/share/lumashield/bpf/

# Copy agent binary from builder
COPY --from=cpp-builder /app/build/lumashield-agent /usr/local/bin/

# Copy default configuration
COPY config/agent.conf /etc/lumashield/agent.conf

# Set capabilities (required for BPF)
# Note: This requires --privileged or specific capabilities when running
# RUN setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/local/bin/lumashield-agent

# Environment variables
ENV LUMASHIELD_BPF_PATH=/usr/share/lumashield/bpf/firewall.bpf.o
ENV LUMASHIELD_INTERFACE=eth0
ENV LUMASHIELD_CONTROL_PLANE=control-plane:50051

# Default command
CMD ["lumashield-agent"]
