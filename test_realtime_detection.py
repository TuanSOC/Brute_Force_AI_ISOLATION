#!/usr/bin/env python3
"""
Test Script for Real-time Brute-Force Detection
Test xem hệ thống có bắt được realtime chưa
"""

import os
import sys
import json
import time
from datetime import datetime

# Configuration
LOG_INPUT = "/opt/ai-bruteforce/brute.log"
LOG_OUTPUT = "/var/ossec/logs/brute.log"
SERVICE_NAME = "bruteforce-detector"

def print_colored(text, color="white"):
    """Print colored text"""
    colors = {
        "red": "\033[0;31m",
        "green": "\033[0;32m",
        "yellow": "\033[1;33m",
        "blue": "\033[0;34m",
        "white": "\033[0m"
    }
    print(f"{colors.get(color, '')}{text}\033[0m")

def check_service():
    """Check if service is running"""
    try:
        import subprocess
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False

def get_file_line_count(filepath):
    """Get line count of file"""
    try:
        with open(filepath, 'r') as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def create_test_logs(count=10):
    """Create test logs with brute-force pattern"""
    print_colored(f"\n📝 Creating {count} test logs (brute-force pattern)...", "blue")
    
    test_ip = "192.168.1.100"
    logs_created = []
    
    for i in range(1, count + 1):
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0700"
        username = "admin"
        password = f"password{i}"
        status_code = 320  # Failed login
        
        # Create Wazuh format log
        full_log_data = {
            "timestamp": timestamp,
            "username": username,
            "status_code": status_code,
            "ip": test_ip,
            "password": password
        }
        full_log_str = json.dumps(full_log_data, ensure_ascii=False)
        
        wazuh_log = {
            "timestamp": timestamp,
            "agent": {
                "id": "001",
                "name": "web-server",
                "ip": "192.168.15.10"
            },
            "manager": {
                "name": "Wazuh"
            },
            "id": f"{int(time.time() * 1000)}.{i}",
            "full_log": full_log_str,
            "decoder": {
                "name": "json"
            },
            "data": {
                "timestamp": timestamp,
                "username": username,
                "status_code": str(status_code),
                "ip": test_ip,
                "password": password
            },
            "location": "/var/log/dvwa_auth.log"
        }
        
        # Write to input log
        try:
            os.makedirs(os.path.dirname(LOG_INPUT), exist_ok=True)
            with open(LOG_INPUT, 'a', encoding='utf-8') as f:
                f.write(json.dumps(wazuh_log, ensure_ascii=False) + '\n')
            logs_created.append(i)
            print(f"  ✓ Added log {i}: IP={test_ip}, User={username}, Status={status_code}")
        except Exception as e:
            print_colored(f"  ❌ Error writing log {i}: {e}", "red")
        
        time.sleep(0.3)  # Small delay to simulate real-time
    
    print_colored(f"✅ Created {len(logs_created)} test logs", "green")
    return len(logs_created)

def main():
    """Main test function"""
    print("=" * 50)
    print_colored("🧪 Test Real-time Brute-Force Detection", "blue")
    print("=" * 50)
    print()
    
    # Check if running as root (on Linux)
    if os.name != 'nt' and os.geteuid() != 0:
        print_colored("⚠️  Warning: Not running as root. Some operations may fail.", "yellow")
        print_colored("   On Ubuntu, run with: sudo python3 test_realtime_detection.py", "yellow")
        print()
    
    # Step 1: Check Service Status
    print_colored("📊 Step 1: Checking service status...", "blue")
    if check_service():
        print_colored("✅ Service is running", "green")
    else:
        print_colored("❌ Service is not running", "red")
        print_colored("   Start service with: sudo systemctl start bruteforce-detector", "yellow")
        print()
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    print()
    
    # Step 2: Check Log Files
    print_colored("📁 Step 2: Checking log files...", "blue")
    
    # Check input file
    if not os.path.exists(LOG_INPUT):
        print_colored(f"⚠️  Input log file not found: {LOG_INPUT}", "yellow")
        print("Creating...")
        try:
            os.makedirs(os.path.dirname(LOG_INPUT), exist_ok=True)
            with open(LOG_INPUT, 'w') as f:
                pass
            os.chmod(LOG_INPUT, 0o644)
            print_colored(f"✅ Created: {LOG_INPUT}", "green")
        except Exception as e:
            print_colored(f"❌ Failed to create input file: {e}", "red")
            return
    else:
        print_colored(f"✅ Input log exists: {LOG_INPUT}", "green")
    
    # Check output file
    if not os.path.exists(LOG_OUTPUT):
        print_colored(f"⚠️  Output log file not found: {LOG_OUTPUT}", "yellow")
        print("Creating...")
        try:
            os.makedirs(os.path.dirname(LOG_OUTPUT), exist_ok=True)
            with open(LOG_OUTPUT, 'w') as f:
                pass
            os.chmod(LOG_OUTPUT, 0o644)
            print_colored(f"✅ Created: {LOG_OUTPUT}", "green")
        except Exception as e:
            print_colored(f"❌ Failed to create output file: {e}", "red")
            return
    else:
        print_colored(f"✅ Output log exists: {LOG_OUTPUT}", "green")
        # Clear output log for clean test
        try:
            with open(LOG_OUTPUT, 'w') as f:
                pass
            print_colored("⚠️  Cleared output log for clean test", "yellow")
        except Exception as e:
            print_colored(f"⚠️  Could not clear output log: {e}", "yellow")
    print()
    
    # Step 3: Get initial output log size
    initial_output_size = get_file_line_count(LOG_OUTPUT)
    print_colored(f"📊 Initial output log size: {initial_output_size} lines", "blue")
    print()
    
    # Step 4: Create Test Logs
    logs_created = create_test_logs(count=10)
    if logs_created == 0:
        print_colored("❌ Failed to create test logs", "red")
        return
    print()
    
    # Step 5: Wait for detection
    print_colored("⏳ Waiting 8 seconds for detection...", "yellow")
    for i in range(8, 0, -1):
        print(f"  {i}...", end='\r')
        time.sleep(1)
    print()
    print()
    
    # Step 6: Check output
    final_output_size = get_file_line_count(LOG_OUTPUT)
    detected_count = final_output_size - initial_output_size
    
    print_colored("=" * 50, "blue")
    print_colored("📊 Test Results", "blue")
    print_colored("=" * 50, "blue")
    print()
    print(f"Test Case: Multiple failed logins (10 attempts from same IP)")
    print(f"Logs created: {logs_created}")
    print(f"Initial output size: {initial_output_size} lines")
    print(f"Final output size: {final_output_size} lines")
    print(f"Alerts detected: {detected_count}")
    print()
    
    if detected_count > 0:
        print_colored(f"✅ SUCCESS: Detected {detected_count} brute-force alerts!", "green")
        print()
        print_colored("📋 Detection Output (last 3 lines):", "blue")
        try:
            with open(LOG_OUTPUT, 'r') as f:
                lines = f.readlines()
                for line in lines[-3:]:
                    if line.strip():
                        print(f"  {line.strip()[:100]}...")  # Truncate long lines
        except Exception as e:
            print_colored(f"  Error reading output: {e}", "red")
        print()
        print_colored("✅ TEST PASSED: Real-time detection is working!", "green")
    else:
        print_colored("❌ FAILED: No brute-force detected", "red")
        print()
        print_colored("⚠️  Debugging info:", "yellow")
        print(f"  - Input log size: {get_file_line_count(LOG_INPUT)} lines")
        print(f"  - Output log size: {final_output_size} lines")
        print(f"  - Service status: {'Running' if check_service() else 'Not running'}")
        print()
        print_colored("🔍 Troubleshooting:", "yellow")
        print("  1. Check service logs:")
        print(f"     sudo journalctl -u {SERVICE_NAME} -n 50")
        print()
        print("  2. Check if model exists:")
        print("     ls -lh /root/ai-brute/rebornAI/rebornAI/models/optimized_bruteforce_detector.pkl")
        print()
        print("  3. Check input log:")
        print(f"     tail -20 {LOG_INPUT}")
        print()
        print("  4. Check output log:")
        print(f"     tail -20 {LOG_OUTPUT}")
        print()
        print_colored("❌ TEST FAILED: No detections found", "red")
    
    print()
    print_colored("=" * 50, "blue")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n\n⚠️  Test interrupted by user", "yellow")
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n\n❌ Test error: {e}", "red")
        import traceback
        traceback.print_exc()
        sys.exit(1)

