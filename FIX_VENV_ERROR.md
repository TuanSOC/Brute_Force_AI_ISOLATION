# 🔧 Fix Lỗi Venv trong Systemd Service

## Vấn đề

Service không chạy được với venv:
```
Process: 18426 ExecStart=/root/ai-brute/rebornAI/rebornAI/venv/bin/python3 ... (code=exited, status=1/FAILURE)
```

## Giải pháp: Dùng System Python (Không dùng venv)

### Cách 1: Chạy lại setup.sh (Khuyến nghị)

```bash
cd /root/ai-brute/rebornAI/rebornAI
sudo ./setup.sh
```

Script sẽ tự động:
- ✅ Xóa venv cũ
- ✅ Cài packages vào system Python
- ✅ Cập nhật service file

### Cách 2: Fix thủ công

#### Bước 1: Xóa venv và cài packages vào system Python

```bash
cd /root/ai-brute/rebornAI/rebornAI

# Xóa venv
rm -rf venv

# Cài packages vào system Python
pip3 install --upgrade pip
pip3 install pandas scikit-learn joblib numpy
```

#### Bước 2: Cập nhật Service File

```bash
sudo nano /etc/systemd/system/bruteforce-detector.service
```

Thay đổi `ExecStart` từ:
```ini
ExecStart=/root/ai-brute/rebornAI/rebornAI/venv/bin/python3 ...
```

Thành:
```ini
ExecStart=/usr/bin/python3 /root/ai-brute/rebornAI/rebornAI/realtime_bruteforce_detector.py
Environment="PYTHONUNBUFFERED=1"
```

#### Bước 3: Reload và Restart Service

```bash
sudo systemctl daemon-reload
sudo systemctl restart bruteforce-detector
sudo systemctl status bruteforce-detector
```

## Kiểm tra

```bash
# Check service status
sudo systemctl status bruteforce-detector

# Check logs
sudo journalctl -u bruteforce-detector -n 50

# Check Python packages
python3 -c "import pandas, sklearn, joblib, numpy; print('OK')"
```

## Test Detection

```bash
cd /root/ai-brute/rebornAI/rebornAI
chmod +x test_realtime.sh
sudo ./test_realtime.sh
```

