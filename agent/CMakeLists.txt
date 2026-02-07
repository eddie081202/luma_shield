cmake_minimum_required(VERSION 3.16)
project(lumashield-agent VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(BUILD_BPF "Build BPF programs" ON)
option(BUILD_TESTS "Build tests" OFF)

# Find required packages
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

# Find libbpf
pkg_check_modules(LIBBPF REQUIRED libbpf)

# Find gRPC and Protobuf
find_package(protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${LIBBPF_INCLUDE_DIRS}
)

# ============================================================================
# BPF Programs (compiled separately with clang)
# ============================================================================
if(BUILD_BPF)
    # Find clang for BPF compilation
    find_program(CLANG clang REQUIRED)
    find_program(LLVM_STRIP llvm-strip REQUIRED)
    
    # BPF compilation flags
    set(BPF_CFLAGS 
        -g -O2 -target bpf
        -D__TARGET_ARCH_x86
        -I/usr/include/x86_64-linux-gnu
    )
    
    # Compile BPF programs
    set(BPF_SOURCES
        ${CMAKE_SOURCE_DIR}/src/bpf/firewall.bpf.c
        ${CMAKE_SOURCE_DIR}/src/bpf/stats.bpf.c
    )
    
    foreach(BPF_SRC ${BPF_SOURCES})
        get_filename_component(BPF_NAME ${BPF_SRC} NAME_WE)
        set(BPF_OBJ ${CMAKE_BINARY_DIR}/bpf/${BPF_NAME}.bpf.o)
        
        add_custom_command(
            OUTPUT ${BPF_OBJ}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/bpf
            COMMAND ${CLANG} ${BPF_CFLAGS} -c ${BPF_SRC} -o ${BPF_OBJ}
            COMMAND ${LLVM_STRIP} -g ${BPF_OBJ}
            DEPENDS ${BPF_SRC}
            COMMENT "Building BPF object ${BPF_NAME}.bpf.o"
        )
        
        list(APPEND BPF_OBJECTS ${BPF_OBJ})
    endforeach()
    
    add_custom_target(bpf_programs ALL DEPENDS ${BPF_OBJECTS})
endif()

# ============================================================================
# Agent Executable
# ============================================================================
set(AGENT_SOURCES
    src/main.cpp
    src/agent.cpp
    src/bpf_loader.cpp
    src/grpc/client.cpp
    src/config.cpp
    src/stats_collector.cpp
)

add_executable(lumashield-agent ${AGENT_SOURCES})

target_link_libraries(lumashield-agent
    PRIVATE
        Threads::Threads
        ${LIBBPF_LIBRARIES}
        gRPC::grpc++
        protobuf::libprotobuf
        elf
        z
)

target_include_directories(lumashield-agent
    PRIVATE
        ${LIBBPF_INCLUDE_DIRS}
)

# Add dependency on BPF programs
if(BUILD_BPF)
    add_dependencies(lumashield-agent bpf_programs)
endif()

# ============================================================================
# Installation
# ============================================================================
install(TARGETS lumashield-agent
    RUNTIME DESTINATION bin
)

install(FILES ${BPF_OBJECTS}
    DESTINATION share/lumashield/bpf
)

# ============================================================================
# Tests
# ============================================================================
if(BUILD_TESTS)
    enable_testing()
    # Add tests here
endif()
