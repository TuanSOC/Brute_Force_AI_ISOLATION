#!/bin/bash
# Test Script for Real-time Brute-Force Detection
# Test trên Ubuntu SIEM Wazuh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOG_INPUT="/opt/ai-bruteforce/brute.log"
LOG_OUTPUT="/var/ossec/logs/brute.log"
SERVICE_NAME="bruteforce-detector"
PROJECT_DIR="/root/ai-brute/rebornAI/rebornAI"

echo "=========================================="
echo "🧪 Test Real-time Brute-Force Detection"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root (use sudo)${NC}"
    exit 1
fi

# Step 1: Check Service Status
echo -e "${BLUE}📊 Step 1: Checking service status...${NC}"
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${GREEN}✅ Service is running${NC}"
else
    echo -e "${RED}❌ Service is not running${NC}"
    echo "Starting service..."
    systemctl start "$SERVICE_NAME"
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}✅ Service started${NC}"
    else
        echo -e "${RED}❌ Failed to start service${NC}"
        echo "Check logs: journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
fi
echo ""

# Step 2: Check Log Files
echo -e "${BLUE}📁 Step 2: Checking log files...${NC}"
if [ ! -f "$LOG_INPUT" ]; then
    echo -e "${YELLOW}⚠️  Input log file not found: $LOG_INPUT${NC}"
    echo "Creating..."
    mkdir -p "$(dirname $LOG_INPUT)"
    touch "$LOG_INPUT"
    chmod 644 "$LOG_INPUT"
    echo -e "${GREEN}✅ Created: $LOG_INPUT${NC}"
else
    echo -e "${GREEN}✅ Input log exists: $LOG_INPUT${NC}"
fi

if [ ! -f "$LOG_OUTPUT" ]; then
    echo -e "${YELLOW}⚠️  Output log file not found: $LOG_OUTPUT${NC}"
    echo "Creating..."
    mkdir -p "$(dirname $LOG_OUTPUT)"
    touch "$LOG_OUTPUT"
    chmod 644 "$LOG_OUTPUT"
    echo -e "${GREEN}✅ Created: $LOG_OUTPUT${NC}"
else
    echo -e "${GREEN}✅ Output log exists: $LOG_OUTPUT${NC}"
    # Clear output log for clean test
    echo "" > "$LOG_OUTPUT"
    echo -e "${YELLOW}⚠️  Cleared output log for clean test${NC}"
fi
echo ""

# Step 3: Get initial output log size
INITIAL_OUTPUT_SIZE=$(wc -l < "$LOG_OUTPUT" 2>/dev/null || echo "0")
echo -e "${BLUE}📊 Initial output log size: $INITIAL_OUTPUT_SIZE lines${NC}"
echo ""

# Step 4: Create Test Logs (Brute-Force Pattern)
echo -e "${BLUE}📝 Step 3: Creating test logs (brute-force pattern)...${NC}"
echo ""

# Test Case 1: Multiple failed logins from same IP (brute-force pattern)
echo -e "${YELLOW}Test Case 1: Multiple failed logins from same IP${NC}"
TEST_IP="192.168.1.100"

for i in {1..10}; do
    # Generate timestamp
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3N+0000" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%S.000+0000")
    USERNAME="admin"
    PASSWORD="password${i}"
    STATUS_CODE=320
    
    # Create Wazuh format log
    FULL_LOG="{\"timestamp\":\"${TIMESTAMP}\",\"username\":\"${USERNAME}\",\"status_code\":${STATUS_CODE},\"ip\":\"${TEST_IP}\",\"password\":\"${PASSWORD}\"}"
    
    WAZUH_LOG=$(cat <<EOF
{"timestamp":"${TIMESTAMP}","agent":{"id":"001","name":"web-server","ip":"192.168.15.10"},"manager":{"name":"Wazuh"},"id":"$(date +%s).$(shuf -i 10000-99999 -n 1)","full_log":"${FULL_LOG}","decoder":{"name":"json"},"data":{"timestamp":"${TIMESTAMP}","username":"${USERNAME}","status_code":"${STATUS_CODE}","ip":"${TEST_IP}","password":"${PASSWORD}"},"location":"/var/log/dvwa_auth.log"}
EOF
)
    
    echo "$WAZUH_LOG" >> "$LOG_INPUT"
    echo "  ✓ Added log $i: IP=$TEST_IP, User=$USERNAME, Status=$STATUS_CODE"
    sleep 0.5  # Small delay to simulate real-time
done

echo -e "${GREEN}✅ Test Case 1: Added 10 failed login attempts${NC}"
echo ""

# Wait for detection
echo -e "${YELLOW}⏳ Waiting 5 seconds for detection...${NC}"
sleep 5

# Check output
OUTPUT_SIZE=$(wc -l < "$LOG_OUTPUT" 2>/dev/null || echo "0")
DETECTED_COUNT=$((OUTPUT_SIZE - INITIAL_OUTPUT_SIZE))

if [ "$DETECTED_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✅ SUCCESS: Detected $DETECTED_COUNT brute-force alerts!${NC}"
    echo ""
    echo -e "${BLUE}📋 Detection Output (last 3 lines):${NC}"
    tail -n 3 "$LOG_OUTPUT" | while IFS= read -r line; do
        echo "  $line"
    done
else
    echo -e "${RED}❌ FAILED: No brute-force detected${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  Debugging info:${NC}"
    echo "  - Input log size: $(wc -l < "$LOG_INPUT") lines"
    echo "  - Output log size: $OUTPUT_SIZE lines"
    echo "  - Service status: $(systemctl is-active $SERVICE_NAME)"
    echo ""
    echo "Check service logs:"
    echo "  journalctl -u $SERVICE_NAME -n 20"
fi
echo ""

# Step 5: Summary
echo "=========================================="
echo -e "${BLUE}📊 Test Summary${NC}"
echo "=========================================="
echo ""
echo "Test Case:"
echo "  - Multiple failed logins (10 attempts from same IP)"
echo ""
echo "Results:"
echo "  - Total alerts detected: $DETECTED_COUNT"
echo "  - Input log: $LOG_INPUT ($(wc -l < "$LOG_INPUT") lines)"
echo "  - Output log: $LOG_OUTPUT ($OUTPUT_SIZE lines)"
echo ""

if [ "$DETECTED_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✅ TEST PASSED: Real-time detection is working!${NC}"
    echo ""
    echo -e "${BLUE}📋 View all detections:${NC}"
    echo "  tail -f $LOG_OUTPUT"
    echo ""
    echo -e "${BLUE}📋 View service logs:${NC}"
    echo "  journalctl -u $SERVICE_NAME -f"
else
    echo -e "${RED}❌ TEST FAILED: No detections found${NC}"
    echo ""
    echo -e "${YELLOW}🔍 Troubleshooting:${NC}"
    echo "  1. Check service status:"
    echo "     systemctl status $SERVICE_NAME"
    echo ""
    echo "  2. Check service logs:"
    echo "     journalctl -u $SERVICE_NAME -n 50"
    echo ""
    echo "  3. Check if model exists:"
    echo "     ls -lh $PROJECT_DIR/models/optimized_bruteforce_detector.pkl"
    echo ""
    echo "  4. Check input log:"
    echo "     tail -20 $LOG_INPUT"
    echo ""
    echo "  5. Check Python dependencies:"
    echo "     python3 -c 'import pandas, sklearn, joblib, numpy; print(\"OK\")'"
fi
echo ""

