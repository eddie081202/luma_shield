#!/bin/bash
# LumaShield API Test Script
# Tests the Control Plane REST API

BASE_URL="${LUMASHIELD_API:-http://localhost:8080}"

echo "Testing LumaShield API at $BASE_URL"
echo "========================================"
echo ""

# Health Check
echo "1. Health Check"
curl -s "$BASE_URL/health" | jq .
echo ""

# Readiness Check
echo "2. Readiness Check"
curl -s "$BASE_URL/ready" | jq .
echo ""

# Add to Blacklist
echo "3. Add IP to Blacklist"
curl -s -X POST "$BASE_URL/api/v1/blacklist" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "Test block", "ttl": 3600}' | jq .
echo ""

# Get Blacklist
echo "4. Get Blacklist"
curl -s "$BASE_URL/api/v1/blacklist" | jq .
echo ""

# Check specific IP
echo "5. Check IP Status"
curl -s "$BASE_URL/api/v1/blacklist/192.168.1.100" | jq .
echo ""

# Create Rule
echo "6. Create Firewall Rule"
curl -s -X POST "$BASE_URL/api/v1/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ip_block",
    "target": "10.0.0.50",
    "action": "drop",
    "reason": "Suspicious activity",
    "priority": 100
  }' | jq .
echo ""

# Get Rules
echo "7. Get All Rules"
curl -s "$BASE_URL/api/v1/rules" | jq .
echo ""

# Get Agents
echo "8. Get Connected Agents"
curl -s "$BASE_URL/api/v1/agents" | jq .
echo ""

# Get System Stats
echo "9. Get System Statistics"
curl -s "$BASE_URL/api/v1/stats" | jq .
echo ""

# Remove from Blacklist
echo "10. Remove IP from Blacklist"
curl -s -X DELETE "$BASE_URL/api/v1/blacklist/192.168.1.100" | jq .
echo ""

echo "========================================"
echo "API Tests Complete!"
