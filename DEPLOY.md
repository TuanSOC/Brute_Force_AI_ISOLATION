# Hướng dẫn Deploy Real-time Brute-Force Detection trên Wazuh SIEM

## Yêu cầu

1. **Hệ thống**: Linux (Ubuntu/Debian/CentOS)
2. **Python**: Python 3.8+
3. **Dependencies**: pandas, scikit-learn, joblib, numpy
4. **Model đã train**: File `models/optimized_bruteforce_detector.pkl` phải tồn tại
5. **Quyền root**: Cần để tạo service và thư mục system

## Cấu hình

### Input Log File
- **Path**: `/opt/ai-bruteforce/brute.log`
- **Format**: Wazuh JSON format (mỗi dòng là một JSON object)

### Output Log File
- **Path**: `/var/ossec/logs/brute.log`
- **Format**: Wazuh JSON format với `risk_score` field
- **Chỉ ghi**: Các log phát hiện brute-force

## Cài đặt

### Bước 1: Cài đặt Dependencies

```bash
# Cài đặt Python dependencies
pip3 install pandas scikit-learn joblib numpy

# Hoặc sử dụng virtual environment (khuyến nghị)
cd /path/to/reBorn_AI
python3 -m venv venv
source venv/bin/activate
pip install pandas scikit-learn joblib numpy
```

### Bước 2: Train Model (nếu chưa có)

```bash
cd /path/to/reBorn_AI/reBorn_AI
python3 optimized_bruteforce_detector.py
```

Model sẽ được lưu tại: `models/optimized_bruteforce_detector.pkl`

### Bước 3: Deploy Service

#### Cách 1: Sử dụng script tự động (khuyến nghị)

```bash
cd /path/to/reBorn_AI/reBorn_AI
chmod +x deploy_realtime.sh
sudo ./deploy_realtime.sh
```

#### Cách 2: Deploy thủ công

1. **Tạo thư mục cần thiết:**

```bash
sudo mkdir -p /opt/ai-bruteforce
sudo mkdir -p /var/ossec/logs
sudo chmod 755 /opt/ai-bruteforce
sudo chmod 755 /var/ossec/logs
```

2. **Tạo file log input (nếu chưa có):**

```bash
sudo touch /opt/ai-bruteforce/brute.log
sudo chmod 644 /opt/ai-bruteforce/brute.log
```

3. **Tạo systemd service file:**

```bash
sudo nano /etc/systemd/system/bruteforce-detector.service
```

Thêm nội dung:

```ini
[Unit]
Description=Real-time Brute-Force Detection Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/reBorn_AI/reBorn_AI
ExecStart=/usr/bin/python3 /path/to/reBorn_AI/reBorn_AI/realtime_bruteforce_detector.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Lưu ý**: Thay `/path/to/reBorn_AI` bằng đường dẫn thực tế của project.

4. **Khởi động service:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable bruteforce-detector
sudo systemctl start bruteforce-detector
```

### Bước 4: Kiểm tra

#### Kiểm tra service status:

```bash
sudo systemctl status bruteforce-detector
```

#### Xem logs:

```bash
# Xem logs của service
sudo journalctl -u bruteforce-detector -f

# Xem output detection (chỉ các log phát hiện brute-force)
sudo tail -f /var/ossec/logs/brute.log
```

## Cấu hình Detection

File: `realtime_bruteforce_detector.py`

### Detection Threshold

```python
DETECTION_THRESHOLD = -0.05  # Hoặc None để dùng model default
```

### Rule-based Detection

```python
RULE_1_ENABLED = False   # Username enumeration
RULE_2_ENABLED = False   # Password spraying
RULE_3_ENABLED = False   # High request rate
RULE_4_ENABLED = False   # False positive filter
```

Để bật rule-based detection, set `True` cho các rule tương ứng.

## Test với Log Mẫu

### Tạo file test log:

```bash
sudo tee -a /opt/ai-bruteforce/brute.log << 'EOF'
{"timestamp":"2025-11-22T12:46:53.078+0700","agent":{"id":"001","name":"web-server","ip":"192.168.15.10"},"manager":{"name":"Wazuh"},"id":"1763790413.16245","full_log":"{\"timestamp\":\"2025-11-22T12:46:51.464+0700\",\"username\":\"admin\",\"status_code\":320,\"ip\":\"192.168.15.12\",\"password\":\"pofanse\"}","decoder":{"name":"json"},"data":{"timestamp":"2025-11-22T12:46:51.464+0700","username":"admin","status_code":"320","ip":"192.168.15.12","password":"pofanse"},"location":"/var/log/dvwa_auth.log"}
{"timestamp":"2025-11-22T12:46:53.081+0700","agent":{"id":"001","name":"web-server","ip":"192.168.15.10"},"manager":{"name":"Wazuh"},"id":"1763790413.16245","full_log":"{\"timestamp\":\"2025-11-22T12:46:51.548+0700\",\"username\":\"admin\",\"status_code\":320,\"ip\":\"192.168.15.12\",\"password\":\"pokerman1\"}","decoder":{"name":"json"},"data":{"timestamp":"2025-11-22T12:46:51.548+0700","username":"admin","status_code":"320","ip":"192.168.15.12","password":"pokerman1"},"location":"/var/log/dvwa_auth.log"}
EOF
```

### Kiểm tra output:

```bash
# Chờ vài giây để service xử lý, sau đó check
sudo tail -f /var/ossec/logs/brute.log
```

## Troubleshooting

### Service không start

1. **Kiểm tra logs:**
```bash
sudo journalctl -u bruteforce-detector -n 50
```

2. **Kiểm tra model file:**
```bash
ls -lh /path/to/reBorn_AI/reBorn_AI/models/optimized_bruteforce_detector.pkl
```

3. **Kiểm tra Python path:**
```bash
which python3
python3 --version
```

### Không phát hiện brute-force

1. **Kiểm tra threshold:**
   - Mở file `realtime_bruteforce_detector.py`
   - Điều chỉnh `DETECTION_THRESHOLD` nếu cần

2. **Kiểm tra input log:**
```bash
sudo tail -f /opt/ai-bruteforce/brute.log
```

3. **Kiểm tra service logs:**
```bash
sudo journalctl -u bruteforce-detector -f
```

### Output file không được tạo

1. **Kiểm tra quyền:**
```bash
sudo ls -la /var/ossec/logs/
```

2. **Tạo file nếu chưa có:**
```bash
sudo touch /var/ossec/logs/brute.log
sudo chmod 644 /var/ossec/logs/brute.log
```

## Quản lý Service

```bash
# Start service
sudo systemctl start bruteforce-detector

# Stop service
sudo systemctl stop bruteforce-detector

# Restart service
sudo systemctl restart bruteforce-detector

# Check status
sudo systemctl status bruteforce-detector

# Enable auto-start on boot
sudo systemctl enable bruteforce-detector

# Disable auto-start on boot
sudo systemctl disable bruteforce-detector

# View logs
sudo journalctl -u bruteforce-detector -f
```

## Format Log

### Input Format (Wazuh):

```json
{
  "timestamp": "2025-11-22T12:46:53.078+0700",
  "agent": {
    "id": "001",
    "name": "web-server",
    "ip": "192.168.15.10"
  },
  "manager": {
    "name": "Wazuh"
  },
  "id": "1763790413.16245",
  "full_log": "{\"timestamp\":\"2025-11-22T12:46:51.464+0700\",\"username\":\"admin\",\"status_code\":320,\"ip\":\"192.168.15.12\",\"password\":\"pofanse\"}",
  "decoder": {
    "name": "json"
  },
  "data": {
    "timestamp": "2025-11-22T12:46:51.464+0700",
    "username": "admin",
    "status_code": "320",
    "ip": "192.168.15.12",
    "password": "pofanse"
  },
  "location": "/var/log/dvwa_auth.log"
}
```

### Output Format (Wazuh + risk_score):

```json
{
  "timestamp": "2025-11-22T12:46:53.078+0700",
  "agent": {
    "id": "001",
    "name": "web-server",
    "ip": "192.168.15.10"
  },
  "manager": {
    "name": "Wazuh"
  },
  "id": "1763790413.16245",
  "full_log": "...",
  "decoder": {
    "name": "json"
  },
  "data": {
    "timestamp": "2025-11-22T12:46:51.464+0700",
    "username": "admin",
    "status_code": "320",
    "ip": "192.168.15.12",
    "password": "pofanse"
  },
  "location": "/var/log/dvwa_auth.log",
  "risk_score": 45.67
}
```

## Lưu ý

1. **Real-time Processing**: Service sẽ đọc log mới ngay khi có (không đợi window interval)
2. **Chỉ ghi brute-force**: Chỉ các log phát hiện brute-force mới được ghi vào output file
3. **Auto-restart**: Service tự động restart nếu crash (RestartSec=10)
4. **Memory management**: Tự động cleanup processed alerts để tránh memory leak
5. **Performance**: Sử dụng deque và tail-like reading để tối ưu performance

## Hỗ trợ

Nếu gặp vấn đề, kiểm tra:
1. Service logs: `journalctl -u bruteforce-detector -f`
2. Debug logs: `/var/ossec/logs/detector_debug.log`
3. Model file: `models/optimized_bruteforce_detector.pkl`

