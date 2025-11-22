# Brute-Force AI Detection System - Isolation Forest

Hệ thống phát hiện Brute-Force Attack sử dụng AI (Isolation Forest) kết hợp Rule-based detection cho Wazuh SIEM.

## 🎯 Tính năng

- **Real-time Detection**: Phát hiện brute-force attack ngay khi có log mới
- **Hybrid Detection**: Kết hợp Rule-based và AI-based (Isolation Forest)
- **Wazuh Integration**: Tích hợp với Wazuh SIEM format
- **High Performance**: Sử dụng tail-like reading để tối ưu performance
- **Production Ready**: Hỗ trợ systemd service, auto-restart, logging

## 📋 Yêu cầu

- Python 3.8+
- pandas, scikit-learn, joblib, numpy
- Ubuntu/Debian (tested on Ubuntu 20.04/22.04)
- Wazuh SIEM

## 🚀 Cài đặt

### 1. Clone Repository

```bash
git clone https://github.com/TuanSOC/Brute_Force_AI_ISOLATION.git
cd Brute_Force_AI_ISOLATION
```

### 2. Cài đặt Dependencies

```bash
pip3 install pandas scikit-learn joblib numpy
```

### 3. Train Model

```bash
cd reBorn_AI
python3 optimized_bruteforce_detector.py
```

### 4. Deploy Service

```bash
chmod +x deploy_realtime.sh
sudo ./deploy_realtime.sh
```

## 📁 Cấu trúc Project

```
reBorn_AI/
├── realtime_bruteforce_detector.py  # Real-time detection service
├── optimized_bruteforce_detector.py # AI model training & detection
├── bruteforce_tracker.py            # IP tracking system
├── check_model.py                   # Model validation tool
├── deploy_realtime.sh               # Deployment script
├── bruteforce-detector.service      # Systemd service file
├── DEPLOY_UBUNTU.md                 # Deployment guide
├── DEPLOY.md                        # General deployment guide
└── models/
    ├── optimized_bruteforce_detector.pkl      # Trained model
    └── optimized_bruteforce_metadata.json     # Model metadata
```

## ⚙️ Cấu hình

### Input/Output

- **Input Log**: `/opt/ai-bruteforce/brute.log` (Wazuh format)
- **Output Alert**: `/var/ossec/logs/brute.log` (chỉ brute-force detected)

### Detection Threshold

Chỉnh sửa trong `realtime_bruteforce_detector.py`:

```python
DETECTION_THRESHOLD = -0.05  # Hoặc None để dùng model default
```

### Rule-based Detection

```python
RULE_1_ENABLED = False   # Username enumeration: >5 usernames/1min
RULE_2_ENABLED = False   # Password spraying: >5 passwords/1min
RULE_3_ENABLED = False   # High request rate: >15 requests/min
RULE_4_ENABLED = False   # False positive filter
```

## 📊 Model Features

Model sử dụng 7 features:

1. `failed_login_rate` - Tỷ lệ login thất bại
2. `unique_usernames_tried` - Số username khác nhau đã thử
3. `unique_passwords_tried` - Số password khác nhau đã thử
4. `time_between_attempts` - Thời gian giữa các lần thử
5. `failed_logins_1min` - Số lần login thất bại trong 1 phút
6. `spamming_username` - Số lần username được dùng (1h)
7. `spamming_password` - Số lần password được dùng (1h)

## 🔍 Detection Logic

### Hybrid Detection Flow

1. **Rule-based Detection (Priority 1)**
   - Rule 1: Username enumeration (>5 usernames/1min)
   - Rule 2: Password spraying (>5 passwords/1min)
   - Rule 3: High request rate (>15 requests/min)
   - Nếu có pattern → ANOMALY ngay

2. **AI-based Detection**
   - Isolation Forest: Score < threshold → anomaly
   - Rule 4: False positive filter (tổng log < 3)

3. **Output**
   - Chỉ ghi các log phát hiện brute-force
   - Thêm `risk_score` vào Wazuh format

## 📖 Sử dụng

### Kiểm tra Service Status

```bash
sudo systemctl status bruteforce-detector
```

### Xem Logs

```bash
# Service logs
sudo journalctl -u bruteforce-detector -f

# Detection alerts
sudo tail -f /var/ossec/logs/brute.log

# Debug logs
sudo tail -f /var/ossec/logs/detector_debug.log
```

### Quản lý Service

```bash
# Start/Stop/Restart
sudo systemctl start bruteforce-detector
sudo systemctl stop bruteforce-detector
sudo systemctl restart bruteforce-detector

# Enable/Disable auto-start
sudo systemctl enable bruteforce-detector
sudo systemctl disable bruteforce-detector
```

## 🧪 Test

### Test với Log Mẫu

```bash
sudo tee -a /opt/ai-bruteforce/brute.log << 'EOF'
{"timestamp":"2025-11-22T12:46:53.078+0700","agent":{"id":"001","name":"web-server","ip":"192.168.15.10"},"manager":{"name":"Wazuh"},"id":"1763790413.16245","full_log":"{\"timestamp\":\"2025-11-22T12:46:51.464+0700\",\"username\":\"admin\",\"status_code\":320,\"ip\":\"192.168.15.12\",\"password\":\"pofanse\"}","decoder":{"name":"json"},"data":{"timestamp":"2025-11-22T12:46:51.464+0700","username":"admin","status_code":"320","ip":"192.168.15.12","password":"pofanse"},"location":"/var/log/dvwa_auth.log"}
EOF

# Kiểm tra output
sudo tail -f /var/ossec/logs/brute.log
```

## 📝 Documentation

- [Deployment Guide (Ubuntu)](DEPLOY_UBUNTU.md)
- [General Deployment Guide](DEPLOY.md)

## 🤝 Đóng góp

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License.

## 👤 Author

**TuanSOC**
- GitHub: [@TuanSOC](https://github.com/TuanSOC)
- Repository: [Brute_Force_AI_ISOLATION](https://github.com/TuanSOC/Brute_Force_AI_ISOLATION)

## 🙏 Acknowledgments

- Wazuh SIEM
- Scikit-learn (Isolation Forest)
- Ubuntu Community

