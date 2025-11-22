#!/bin/bash
# Auto Setup Script for Brute-Force AI Detection System on Wazuh SIEM
# Chạy script này để tự động cài đặt và deploy hệ thống

set -e

echo "=========================================="
echo "🚀 Auto Setup - Brute-Force AI Detection"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/TuanSOC/Brute_Force_AI_ISOLATION.git"
PROJECT_DIR="/root/ai-brute/rebornAI/rebornAI"
LOG_INPUT="/opt/ai-bruteforce/brute.log"
LOG_OUTPUT="/var/ossec/logs/brute.log"
SERVICE_NAME="bruteforce-detector"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Running as root${NC}"
echo ""

# Step 1: Check Python
echo "📦 Step 1: Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 not found. Installing...${NC}"
    apt-get update
    apt-get install -y python3 python3-pip python3-venv
else
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✅ Found: $PYTHON_VERSION${NC}"
fi
echo ""

# Step 2: Clone or Update Repository
echo "📥 Step 2: Setting up repository..."
if [ -d "$PROJECT_DIR" ]; then
    echo -e "${YELLOW}⚠️  Directory exists: $PROJECT_DIR${NC}"
    read -p "Update existing repository? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Updating repository..."
        cd "$PROJECT_DIR"
        git pull origin main || echo "Git pull failed, continuing..."
    else
        echo "Using existing directory..."
    fi
else
    echo "Creating directory and cloning repository..."
    mkdir -p "$(dirname $PROJECT_DIR)"
    git clone "$REPO_URL" "$PROJECT_DIR" || {
        echo -e "${RED}❌ Failed to clone repository${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ Repository cloned${NC}"
fi

cd "$PROJECT_DIR"
echo -e "${GREEN}✅ Repository ready${NC}"
echo ""

# Step 3: Install Dependencies
echo "📦 Step 3: Installing Python dependencies..."
if [ -d "venv" ]; then
    echo "Virtual environment exists, activating..."
    source venv/bin/activate
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
fi

echo "Installing packages..."
pip install --upgrade pip
pip install pandas scikit-learn joblib numpy

echo -e "${GREEN}✅ Dependencies installed${NC}"
echo ""

# Step 4: Check Model
echo "🤖 Step 4: Checking model..."
MODEL_PATH="$PROJECT_DIR/models/optimized_bruteforce_detector.pkl"
if [ ! -f "$MODEL_PATH" ]; then
    echo -e "${YELLOW}⚠️  Model file not found: $MODEL_PATH${NC}"
    read -p "Train model now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Training model..."
        echo -e "${YELLOW}⚠️  Note: You need training data (normal.log) to train the model${NC}"
        if [ -f "normal.log" ] || [ -f "../normal.log" ]; then
            TRAIN_FILE="normal.log"
            if [ ! -f "$TRAIN_FILE" ]; then
                TRAIN_FILE="../normal.log"
            fi
            echo "Using training file: $TRAIN_FILE"
            python3 optimized_bruteforce_detector.py || {
                echo -e "${RED}❌ Model training failed${NC}"
                echo "You can train the model later manually"
            }
        else
            echo -e "${YELLOW}⚠️  Training data (normal.log) not found${NC}"
            echo "You can train the model later using:"
            echo "  cd $PROJECT_DIR"
            echo "  source venv/bin/activate"
            echo "  python3 optimized_bruteforce_detector.py"
        fi
    else
        echo -e "${YELLOW}⚠️  Model training skipped. You need to train the model before running the service.${NC}"
    fi
else
    echo -e "${GREEN}✅ Model file found: $MODEL_PATH${NC}"
fi
echo ""

# Step 5: Create Directories
echo "📁 Step 5: Creating directories..."
mkdir -p /opt/ai-bruteforce
mkdir -p /var/ossec/logs
chmod 755 /opt/ai-bruteforce
chmod 755 /var/ossec/logs

# Create log files if they don't exist
if [ ! -f "$LOG_INPUT" ]; then
    touch "$LOG_INPUT"
    chmod 644 "$LOG_INPUT"
    echo -e "${GREEN}✅ Created: $LOG_INPUT${NC}"
fi

if [ ! -f "$LOG_OUTPUT" ]; then
    touch "$LOG_OUTPUT"
    chmod 644 "$LOG_OUTPUT"
    echo -e "${GREEN}✅ Created: $LOG_OUTPUT${NC}"
fi

echo -e "${GREEN}✅ Directories created${NC}"
echo ""

# Step 6: Create Systemd Service
echo "⚙️  Step 6: Creating systemd service..."
PYTHON_PATH="$PROJECT_DIR/venv/bin/python3"
if [ ! -f "$PYTHON_PATH" ]; then
    PYTHON_PATH="/usr/bin/python3"
    echo -e "${YELLOW}⚠️  Using system Python: $PYTHON_PATH${NC}"
else
    echo -e "${GREEN}✅ Using venv Python: $PYTHON_PATH${NC}"
fi

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Real-time Brute-Force Detection Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=$PYTHON_PATH $PROJECT_DIR/realtime_bruteforce_detector.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✅ Service file created: $SERVICE_FILE${NC}"
echo ""

# Step 7: Enable and Start Service
echo "🚀 Step 7: Enabling and starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "Service is already running. Restarting..."
    systemctl restart "$SERVICE_NAME"
else
    echo "Starting service..."
    systemctl start "$SERVICE_NAME"
fi

# Wait a moment for service to start
sleep 3

# Check service status
echo ""
echo "📊 Service status:"
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${GREEN}✅ Service is running${NC}"
else
    echo -e "${RED}❌ Service failed to start${NC}"
    echo "Check logs with: journalctl -u $SERVICE_NAME -n 50"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}✅ Setup completed!${NC}"
echo "=========================================="
echo ""
echo "📋 Configuration:"
echo "   - Project dir: $PROJECT_DIR"
echo "   - Input log:   $LOG_INPUT"
echo "   - Output log:  $LOG_OUTPUT"
echo "   - Model:       $MODEL_PATH"
echo "   - Service:     $SERVICE_NAME"
echo ""
echo "📋 Useful commands:"
echo "   - Check status:  systemctl status $SERVICE_NAME"
echo "   - View logs:     journalctl -u $SERVICE_NAME -f"
echo "   - Restart:       systemctl restart $SERVICE_NAME"
echo "   - Stop:          systemctl stop $SERVICE_NAME"
echo ""
echo "📋 Check detection output:"
echo "   tail -f $LOG_OUTPUT"
echo ""
echo -e "${GREEN}🎉 Setup complete! The service is now running.${NC}"
echo ""

