# 📁 Project Structure

## Cấu trúc Project

```
reBorn_AI/
├── 📄 Core Python Files
│   ├── realtime_bruteforce_detector.py    # Real-time detection service
│   ├── optimized_bruteforce_detector.py   # AI model training & detection
│   ├── bruteforce_tracker.py              # IP tracking system
│   └── check_model.py                     # Model validation tool
│
├── 🚀 Deployment Scripts
│   ├── setup.sh                           # Auto setup script (one-command)
│   └── deploy_realtime.sh                 # Manual deployment script
│
├── ⚙️  Configuration Files
│   ├── bruteforce-detector.service        # Systemd service file
│   ├── .gitignore                         # Git ignore rules
│   └── .gitattributes                     # Git attributes (line endings)
│
├── 📚 Documentation
│   ├── README.md                          # Main documentation
│   ├── QUICK_START.md                     # Quick start guide
│   ├── DEPLOY.md                          # General deployment guide
│   ├── DEPLOY_UBUNTU.md                   # Ubuntu deployment guide
│   └── PROJECT_STRUCTURE.md               # This file
│
└── 🤖 Models (metadata only)
    └── models/
        └── optimized_bruteforce_metadata.json  # Model metadata
```

## Files được Git Track

### ✅ Source Code
- `realtime_bruteforce_detector.py` - Real-time detection
- `optimized_bruteforce_detector.py` - AI model
- `bruteforce_tracker.py` - Tracking system
- `check_model.py` - Validation tool

### ✅ Deployment
- `setup.sh` - Auto setup
- `deploy_realtime.sh` - Manual deploy
- `bruteforce-detector.service` - Systemd service

### ✅ Documentation
- `README.md` - Main docs
- `QUICK_START.md` - Quick start
- `DEPLOY.md` - Deployment guide
- `DEPLOY_UBUNTU.md` - Ubuntu guide

### ✅ Configuration
- `.gitignore` - Git ignore
- `.gitattributes` - Line endings
- `models/optimized_bruteforce_metadata.json` - Model metadata

## Files KHÔNG được Track (theo .gitignore)

### ❌ Python Cache
- `__pycache__/` - Python bytecode cache
- `*.pyc`, `*.pyo` - Compiled Python files

### ❌ Virtual Environment
- `venv/` - Virtual environment (tạo khi setup)

### ❌ Logs
- `*.log` - Log files
- `ai_bruteforce_detection.log` - Detection logs

### ❌ Model Files (quá lớn)
- `*.pkl` - Trained model files
- `models/*.pkl` - Model binaries
- `models/*.backup` - Backup files

### ❌ Training Data
- `normal.log` - Training data (có thể rất lớn)
- `*.csv` - CSV files

### ❌ Backup Files
- `*.backup` - Backup files
- `*.bak` - Backup files

## Deployment Paths

### Production Paths (Ubuntu)
- **Project**: `/root/ai-brute/rebornAI/rebornAI/`
- **Input Log**: `/opt/ai-bruteforce/brute.log`
- **Output Alert**: `/var/ossec/logs/brute.log`
- **Service**: `bruteforce-detector`

## Quick Commands

### Setup
```bash
git clone https://github.com/TuanSOC/Brute_Force_AI_ISOLATION.git
cd Brute_Force_AI_ISOLATION/reBorn_AI
chmod +x setup.sh
sudo ./setup.sh
```

### Service Management
```bash
sudo systemctl status bruteforce-detector
sudo systemctl restart bruteforce-detector
sudo journalctl -u bruteforce-detector -f
```

### Check Output
```bash
sudo tail -f /var/ossec/logs/brute.log
```

