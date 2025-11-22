# 🚀 Quick Start Guide

## Cài đặt Tự động (1 Lệnh)

### Trên Ubuntu/Debian Server:

```bash
# Cách 1: Clone và chạy setup
git clone https://github.com/TuanSOC/Brute_Force_AI_ISOLATION.git
cd Brute_Force_AI_ISOLATION/reBorn_AI
chmod +x setup.sh
sudo ./setup.sh
```

### Hoặc chạy trực tiếp từ GitHub (nếu có curl/wget):

```bash
# Với curl
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/TuanSOC/Brute_Force_AI_ISOLATION/main/reBorn_AI/setup.sh)"

# Với wget
sudo bash <(wget -qO- https://raw.githubusercontent.com/TuanSOC/Brute_Force_AI_ISOLATION/main/reBorn_AI/setup.sh)
```

## Script Setup Sẽ Tự Động:

1. ✅ Kiểm tra và cài đặt Python 3
2. ✅ Clone/Update repository về `/root/ai-brute/rebornAI/rebornAI/`
3. ✅ Tạo virtual environment
4. ✅ Cài đặt dependencies (pandas, scikit-learn, joblib, numpy)
5. ✅ Kiểm tra model (hỏi có muốn train nếu chưa có)
6. ✅ Tạo thư mục cần thiết (`/opt/ai-bruteforce`, `/var/ossec/logs`)
7. ✅ Tạo systemd service (`bruteforce-detector`)
8. ✅ Enable và start service tự động

## Sau Khi Setup:

### Kiểm tra Service:

```bash
# Status
sudo systemctl status bruteforce-detector

# Logs
sudo journalctl -u bruteforce-detector -f

# Output detection
sudo tail -f /var/ossec/logs/brute.log
```

### Quản lý Service:

```bash
# Restart
sudo systemctl restart bruteforce-detector

# Stop
sudo systemctl stop bruteforce-detector

# Start
sudo systemctl start bruteforce-detector
```

## Cấu Hình:

- **Input Log**: `/opt/ai-bruteforce/brute.log` (Wazuh format)
- **Output Alert**: `/var/ossec/logs/brute.log` (chỉ brute-force detected)
- **Service**: `bruteforce-detector`
- **Project Path**: `/root/ai-brute/rebornAI/rebornAI/`

## Lưu Ý:

1. **Model Training**: Nếu chưa có model, script sẽ hỏi có muốn train không. Bạn cần file `normal.log` (training data) để train model.

2. **Training Data**: Nếu không có `normal.log`, bạn có thể train sau:
   ```bash
   cd /root/ai-brute/rebornAI/rebornAI
   source venv/bin/activate
   python3 optimized_bruteforce_detector.py
   ```

3. **Service Auto-restart**: Service sẽ tự động restart nếu crash (RestartSec=10)

4. **Real-time Detection**: Service sẽ đọc log mới ngay khi có và detect brute-force attack

## Troubleshooting:

### Service không start:

```bash
# Xem logs
sudo journalctl -u bruteforce-detector -n 50

# Kiểm tra model
ls -lh /root/ai-brute/rebornAI/rebornAI/models/optimized_bruteforce_detector.pkl
```

### Không phát hiện brute-force:

- Kiểm tra input log: `sudo tail -f /opt/ai-bruteforce/brute.log`
- Kiểm tra threshold trong `realtime_bruteforce_detector.py`
- Xem service logs để debug

## Test:

```bash
# Thêm log test
sudo tee -a /opt/ai-bruteforce/brute.log << 'EOF'
{"timestamp":"2025-11-22T12:46:53.078+0700","agent":{"id":"001","name":"web-server","ip":"192.168.15.10"},"manager":{"name":"Wazuh"},"id":"1763790413.16245","full_log":"{\"timestamp\":\"2025-11-22T12:46:51.464+0700\",\"username\":\"admin\",\"status_code\":320,\"ip\":\"192.168.15.12\",\"password\":\"pofanse\"}","decoder":{"name":"json"},"data":{"timestamp":"2025-11-22T12:46:51.464+0700","username":"admin","status_code":"320","ip":"192.168.15.12","password":"pofanse"},"location":"/var/log/dvwa_auth.log"}
EOF

# Kiểm tra output
sudo tail -f /var/ossec/logs/brute.log
```

## 🎉 Xong!

Sau khi chạy `setup.sh`, hệ thống sẽ tự động chạy và sẵn sàng phát hiện brute-force attacks!

