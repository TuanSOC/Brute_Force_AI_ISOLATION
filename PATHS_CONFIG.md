# 📍 Paths Configuration - Systemd Service

## Paths Chuẩn (Hardcoded)

### Input Log File
- **Path**: `/opt/ai-bruteforce/brute.log`
- **Format**: Wazuh JSON format (mỗi dòng là một JSON object)
- **Permission**: Read-only cho service
- **Validation**: 
  - Kiểm tra file tồn tại khi start
  - Tự động tạo nếu không tồn tại
  - Kiểm tra quyền đọc

### Output Alert File
- **Path**: `/var/ossec/logs/brute.log`
- **Format**: Wazuh JSON format với `risk_score` field
- **Permission**: Write cho service
- **Validation**:
  - Kiểm tra thư mục tồn tại
  - Tự động tạo thư mục nếu không tồn tại
  - Kiểm tra quyền ghi
  - Chỉ ghi các log phát hiện brute-force

### Model File
- **Path**: `/root/ai-brute/rebornAI/rebornAI/models/optimized_bruteforce_detector.pkl`
- **Auto-resolve**: Tự động resolve từ script location
- **Validation**: Kiểm tra tồn tại khi start, exit nếu không có

## Validation Logic

### Startup Validation

1. **Input Log File**:
   ```python
   INPUT_LOG_FILE = '/opt/ai-bruteforce/brute.log'
   - Check exists
   - Create if not exists
   - Check read permission
   ```

2. **Output Directory**:
   ```python
   OUTPUT_ALERT_FILE = '/var/ossec/logs/brute.log'
   - Check directory exists
   - Create directory if not exists
   - Check write permission
   ```

3. **Model File**:
   ```python
   model_path = os.path.join(os.path.dirname(__file__), 'models/optimized_bruteforce_detector.pkl')
   - Check exists
   - Exit if not found
   ```

### Runtime Validation

1. **Read Input**:
   - Check file exists before reading
   - Check read permission
   - Handle file rotation (seek to end if file truncated)

2. **Write Output**:
   - Check directory exists
   - Check write permission
   - Handle permission errors gracefully

## Service File Configuration

```ini
[Service]
WorkingDirectory=/root/ai-brute/rebornAI/rebornAI
ExecStart=/usr/bin/python3 /root/ai-brute/rebornAI/rebornAI/realtime_bruteforce_detector.py
```

**Lưu ý**: 
- `WorkingDirectory` phải đúng để model path resolve đúng
- `ExecStart` dùng system Python (không venv)

## Logging

Service sẽ log rõ ràng paths khi start:

```
📥 INPUT LOG:  /opt/ai-bruteforce/brute.log
📤 OUTPUT LOG: /var/ossec/logs/brute.log
🤖 MODEL:      /root/ai-brute/rebornAI/rebornAI/models/optimized_bruteforce_detector.pkl
```

## Troubleshooting

### Input file not found
```bash
# Check file exists
ls -lh /opt/ai-bruteforce/brute.log

# Check permissions
ls -la /opt/ai-bruteforce/

# Create if needed
sudo mkdir -p /opt/ai-bruteforce
sudo touch /opt/ai-bruteforce/brute.log
sudo chmod 644 /opt/ai-bruteforce/brute.log
```

### Output file permission denied
```bash
# Check directory
ls -la /var/ossec/logs/

# Create directory if needed
sudo mkdir -p /var/ossec/logs
sudo chmod 755 /var/ossec/logs

# Check service can write
sudo -u root touch /var/ossec/logs/brute.log
```

### Model file not found
```bash
# Check model exists
ls -lh /root/ai-brute/rebornAI/rebornAI/models/optimized_bruteforce_detector.pkl

# Train model if needed
cd /root/ai-brute/rebornAI/rebornAI
python3 optimized_bruteforce_detector.py
```

## Test Paths

```bash
# Test read input
cat /opt/ai-bruteforce/brute.log

# Test write output
echo '{"test": "data"}' | sudo tee -a /var/ossec/logs/brute.log

# Check service logs
sudo journalctl -u bruteforce-detector -n 50 | grep -i "input\|output\|path"
```

