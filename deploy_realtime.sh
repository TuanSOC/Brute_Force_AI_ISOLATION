#!/bin/bash
# Script deploy Real-time Brute-Force Detection trên Wazuh SIEM
# Path: /root/ai-brute/rebornAI/rebornAI/

set -e

echo "=========================================="
echo "🚀 Deploy Real-time Brute-Force Detection"
echo "=========================================="

# Configuration - PATH MỚI
PROJECT_DIR="/root/ai-brute/rebornAI/rebornAI"
LOG_INPUT="/opt/ai-bruteforce/brute.log"
LOG_OUTPUT="/var/ossec/logs/brute.log"
SERVICE_NAME="bruteforce-detector"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Check if project directory exists
if [ ! -d "$PROJECT_DIR" ]; then
    echo "❌ Project directory not found: $PROJECT_DIR"
    echo "   Please ensure the project is deployed to $PROJECT_DIR"
    exit 1
fi

echo "✅ Project directory found: $PROJECT_DIR"

# Check if realtime script exists
REALTIME_SCRIPT="$PROJECT_DIR/realtime_bruteforce_detector.py"
if [ ! -f "$REALTIME_SCRIPT" ]; then
    echo "❌ Real-time script not found: $REALTIME_SCRIPT"
    exit 1
fi

echo "✅ Real-time script found: $REALTIME_SCRIPT"

# Check if model exists
MODEL_PATH="$PROJECT_DIR/models/optimized_bruteforce_detector.pkl"
if [ ! -f "$MODEL_PATH" ]; then
    echo "❌ Model file not found: $MODEL_PATH"
    echo "   Please train the model first using:"
    echo "   python3 $PROJECT_DIR/optimized_bruteforce_detector.py"
    exit 1
fi

echo "✅ Model file found: $MODEL_PATH"

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p /opt/ai-bruteforce
mkdir -p /var/ossec/logs
chmod 755 /opt/ai-bruteforce
chmod 755 /var/ossec/logs

# Check if input log file exists, if not create it
if [ ! -f "$LOG_INPUT" ]; then
    echo "⚠️  Input log file not found: $LOG_INPUT"
    echo "   Creating empty file..."
    touch "$LOG_INPUT"
    chmod 644 "$LOG_INPUT"
fi

# Check if output log file exists, if not create it
if [ ! -f "$LOG_OUTPUT" ]; then
    echo "⚠️  Output log file not found: $LOG_OUTPUT"
    echo "   Creating empty file..."
    touch "$LOG_OUTPUT"
    chmod 644 "$LOG_OUTPUT"
fi

echo "✅ Directories created"

# Create systemd service file
echo ""
echo "📝 Creating systemd service file..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Real-time Brute-Force Detection Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/python3 $REALTIME_SCRIPT
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Service file created: $SERVICE_FILE"

# Reload systemd
echo ""
echo "🔄 Reloading systemd..."
systemctl daemon-reload

# Enable service
echo ""
echo "⚙️  Enabling service..."
systemctl enable "$SERVICE_NAME"

# Check if service is already running
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo "🔄 Service is already running. Restarting..."
    systemctl restart "$SERVICE_NAME"
else
    echo ""
    echo "🚀 Starting service..."
    systemctl start "$SERVICE_NAME"
fi

# Wait a moment for service to start
sleep 2

# Check service status
echo ""
echo "📊 Service status:"
systemctl status "$SERVICE_NAME" --no-pager -l || true

echo ""
echo "=========================================="
echo "✅ Deployment completed!"
echo "=========================================="
echo ""
echo "📋 Configuration:"
echo "   - Project dir: $PROJECT_DIR"
echo "   - Input log:   $LOG_INPUT"
echo "   - Output log:  $LOG_OUTPUT"
echo "   - Model:       $MODEL_PATH"
echo "   - Script:      $REALTIME_SCRIPT"
echo ""
echo "📋 Useful commands:"
echo "   - Check status:  systemctl status $SERVICE_NAME"
echo "   - View logs:     journalctl -u $SERVICE_NAME -f"
echo "   - Restart:       systemctl restart $SERVICE_NAME"
echo "   - Stop:          systemctl stop $SERVICE_NAME"
echo "   - Start:         systemctl start $SERVICE_NAME"
echo ""
echo "📋 Check detection output:"
echo "   tail -f $LOG_OUTPUT"
echo ""
