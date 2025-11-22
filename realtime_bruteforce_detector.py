#!/usr/bin/env python3
"""
Real-time Brute-Force Detection for Ubuntu
- Reads from /opt/ai-bruteforce/brute.log (Wazuh format)
- Detects brute-force attacks using trained model
- Writes alerts to /var/ossec/logs/brute.log
- Supports Ctrl+C graceful shutdown
- Real-time monitoring with initial scan
"""

import os
import sys
import json
import time
import signal
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from collections import deque
import traceback

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from optimized_bruteforce_detector import OptimizedBruteForceDetector

# Setup logging
# Set level to DEBUG để xem debug logs
log_dir = '/var/ossec/logs'
os.makedirs(log_dir, exist_ok=True)

# Main log file
main_log_file = os.path.join(log_dir, 'detector.log')
# Debug log file riêng
debug_log_file = os.path.join(log_dir, 'detector_debug.log')

# Setup handlers
handlers = [
    logging.FileHandler(main_log_file),
    logging.StreamHandler()
]

# Debug handler riêng (chỉ ghi DEBUG level)
debug_handler = logging.FileHandler(debug_log_file)
debug_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
debug_handler.setFormatter(debug_formatter)

logging.basicConfig(
    level=logging.DEBUG,  # Đổi từ INFO sang DEBUG để xem debug logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers
)

logger = logging.getLogger(__name__)
# Thêm debug handler riêng
logger.addHandler(debug_handler)

# Global variables
detector = None
running = True
last_position = 0  # Track file position for tail (used in read_new_logs_from_position)

# Configuration - ĐIỀU CHỈNH ĐỘ NHẠY Ở ĐÂY
# Isolation Forest: score càng THẤP = càng bất thường
# score < threshold → anomaly (brute-force)
# Use None to use model's default threshold (50th percentile from training)
DETECTION_THRESHOLD = -0.05  # None = use model default (0.091730), or set custom value

# Window-based detection configuration
WINDOW_INTERVAL_SECONDS = 10  # Process every 10 seconds
FEATURE_WINDOW_SECONDS = 60   # Calculate features from logs in last 60 seconds

# Rule-based detection configuration
# Set to True to enable rule, False to disable
RULE_1_ENABLED = False   # Username enumeration: >5 different usernames in 1 minute
RULE_2_ENABLED = False   # Password spraying: >5 passwords for 1 user in 1 minute
RULE_3_ENABLED = False   # High request rate: >15 requests/minute from 1 IP
RULE_4_ENABLED = False   # False positive filter: AI detected but total logs < 3


def get_rule_flags():
    """Get rule flags dictionary from configuration"""
    return {
        'rule_1': RULE_1_ENABLED,
        'rule_2': RULE_2_ENABLED,
        'rule_3': RULE_3_ENABLED,
        'rule_4': RULE_4_ENABLED
    }


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    logger.info("\n🛑 Received interrupt signal (Ctrl+C). Shutting down gracefully...")
    running = False
    sys.exit(0)


def parse_wazuh_log(line: str) -> Optional[tuple]:
    """
    Parse Wazuh log format to extract authentication data
    
    Input format:
    {
        "timestamp":"2025-11-16T18:37:07.603+0700",
        "agent":{"id":"001","name":"web-server","ip":"127.0.0.1"},
        "manager":{"name":"Wazuh"},
        "id":"6919b7639371d3.19135906",
        "full_log":"{\"timestamp\":\"2025-11-16T18:37:07.603+0700\",\"username\":\"admin\",\"status_code\":200,\"ip\":\"127.0.0.1\",\"password\":\"password\"}",
        "decoder":{"name":"json"},
        "data":{"timestamp":"2025-11-16T18:37:07.603+0700","username":"admin","status_code":"200","ip":"127.0.0.1"},
        "location":"/opt/ai-bruteforce/brute.log"
    }
    
    Returns:
        Tuple: (auth_data_dict, wazuh_entry_dict) or None
        - auth_data_dict: Dict with: timestamp, username, password, status_code, ip
        - wazuh_entry_dict: Original Wazuh entry for output format reconstruction
    """
    try:
        # Parse outer JSON
        wazuh_entry = json.loads(line.strip())
        
        # Try to get data from nested full_log first (most complete)
        auth_data = None
        if 'full_log' in wazuh_entry:
            try:
                full_log_str = wazuh_entry['full_log']
                # Handle escaped JSON string
                if isinstance(full_log_str, str):
                    # full_log is already a JSON string, parse it directly
                    # It may be double-encoded, so try parsing multiple times
                    try:
                        auth_data = json.loads(full_log_str)
                    except json.JSONDecodeError:
                        # Try unescaping first
                        import codecs
                        unescaped = codecs.decode(full_log_str, 'unicode_escape')
                        auth_data = json.loads(unescaped)
            except (json.JSONDecodeError, TypeError) as e:
                logger.debug(f"Could not parse full_log: {e}")
        
        # Fallback to 'data' field
        if not auth_data and 'data' in wazuh_entry:
            auth_data = wazuh_entry['data']
        
        # If still no data, try to construct from available fields
        if not auth_data:
            auth_data = {}
            if 'timestamp' in wazuh_entry:
                auth_data['timestamp'] = wazuh_entry['timestamp']
            if 'agent' in wazuh_entry and 'ip' in wazuh_entry['agent']:
                auth_data['ip'] = wazuh_entry['agent']['ip']
        
        # Extract required fields
        # Handle status_code as string or int
        status_code = 0
        if 'status_code' in auth_data:
            status_code_str = str(auth_data['status_code'])
            try:
                status_code = int(status_code_str)
            except ValueError:
                status_code = 0
        
        result = {
            'timestamp': auth_data.get('timestamp', wazuh_entry.get('timestamp', '')),
            'username': auth_data.get('username', ''),
            'password': auth_data.get('password', ''),
            'status_code': status_code,
            'ip': auth_data.get('ip', wazuh_entry.get('agent', {}).get('ip', ''))
        }
        
        # Validate required fields
        if not result['ip'] or not result['timestamp']:
            logger.debug(f"Missing required fields in log entry: {result}")
            return None
        
        # Return both auth_data and original wazuh_entry
        return (result, wazuh_entry)
        
    except json.JSONDecodeError as e:
        logger.debug(f"JSON decode error: {e}")
        return None
    except Exception as e:
        logger.debug(f"Error parsing log line: {e}")
        return None


def convert_to_detector_format(auth_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert parsed auth data to detector format
    """
    timestamp = auth_data.get('timestamp', '')
    username = auth_data.get('username', '')
    password = auth_data.get('password', '')
    status_code = auth_data.get('status_code', 0)
    ip = auth_data.get('ip', '')
    
    # Build payload
    payload_parts = []
    if username:
        payload_parts.append(f"username={username}")
    if password:
        payload_parts.append(f"password={password}")
    payload = "&".join(payload_parts)
    
    # Convert to detector format
    detector_entry = {
        'remote_ip': ip,
        'uri': '/login',
        'method': 'POST',
        'status': status_code,
        'payload': payload,
        'query_string': '',
        'time': timestamp,
        'request_length': len(payload),
        'response_length': 0,
        'response_time_ms': 0,
        'bytes_sent': 0,
        'body': '',
        'cookie': '',
        'user_agent': '',
        'referer': ''
    }
    
    return detector_entry


def log_detection_details(auth_data: Dict[str, Any], detection_result: tuple, detect_duration_ms: float):
    """
    Log detailed detection information for detected brute-force attacks only
    
    Args:
        auth_data: Original auth data
        detection_result: Extended tuple from predict_single
        detect_duration_ms: Detection time in milliseconds
    """
    # Unpack extended result tuple
    if len(detection_result) >= 9:
        is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score, raw_anomaly_score, decision_threshold, features = detection_result
    else:
        # Fallback for old format
        is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score = detection_result[:6]
        raw_anomaly_score = None
        # Use model default if DETECTION_THRESHOLD is None
        decision_threshold = DETECTION_THRESHOLD if DETECTION_THRESHOLD is not None else 0.091730
        features = {}
    
    ip = auth_data.get('ip', 'unknown')
    username = auth_data.get('username', 'unknown')
    status_code = auth_data.get('status_code', 0)
    log_timestamp = auth_data.get('timestamp', 'unknown')
    
    # Extract key features for logging
    # Note: requests_per_minute and requests_per_second are no longer extracted as features
    # They are still calculated in tracker but not used for training
    failed_login_rate = features.get('failed_login_rate', 0) if features else 0
    unique_usernames = features.get('unique_usernames_tried', 0) if features else 0
    unique_passwords = features.get('unique_passwords_tried', 0) if features else 0
    failed_logins_1min = features.get('failed_logins_1min', 0) if features else 0
    has_username_enum = features.get('has_username_enumeration', 0) if features else 0
    has_password_spray = features.get('has_password_spraying', 0) if features else 0
    
    # Determine status icon
    status_icon = "🚨" if is_bruteforce else "✓"
    status_text = "BRUTE-FORCE DETECTED" if is_bruteforce else "Normal"
    
    # Format raw anomaly score (handle None case)
    raw_score_str = f"{raw_anomaly_score:.6f}" if raw_anomaly_score is not None else "N/A"
    
    # Format threshold (handle None case)
    threshold_str = f"{decision_threshold:.6f}" if decision_threshold is not None else "N/A"
    
    # Format log message
    log_msg = (
        f"{status_icon} [{status_text}] "
        f"Time={log_timestamp} | "
        f"IP={ip} | "
        f"User={username} | "
        f"Status={status_code} | "
        f"RawAnomalyScore={raw_score_str} | "
        f"NormalizedScore={normalized_score:.6f} | "
        f"Threshold={threshold_str} | "
        f"RiskScore={risk_score:.2f} | "
        f"Threat={threat_level} | "
        f"Confidence={confidence} | "
        f"FailedRate={failed_login_rate:.2f} | "
        f"UniqueUsers={unique_usernames} | "
        f"UniquePasswords={unique_passwords} | "
        f"FailedLogins1min={failed_logins_1min} | "
        f"UserEnum={has_username_enum} | "
        f"PassSpray={has_password_spray} | "
        f"DetectTime={detect_duration_ms:.2f}ms"
    )
    
    # CHỈ LOG các trường hợp phát hiện brute-force
    if is_bruteforce:
        logger.warning(log_msg)  # Use WARNING for detected attacks to make them stand out
    else:
        logger.debug(log_msg)  # Use DEBUG for normal entries (không log để giảm noise)


def write_alert(log_entry: Dict[str, Any], detection_result: tuple, auth_data: Dict[str, Any], wazuh_entry: Optional[Dict[str, Any]] = None):
    """
    Write brute-force alert to /var/ossec/logs/brute.log in Wazuh format
    
    Args:
        log_entry: Original log entry in detector format
        detection_result: Extended tuple from predict_single
        auth_data: Original auth data
        wazuh_entry: Original Wazuh entry (for format reconstruction)
    
    Output Path: /var/ossec/logs/brute.log (hardcoded for Wazuh SIEM)
    """
    # Unpack extended result tuple
    if len(detection_result) >= 9:
        is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score, raw_anomaly_score, decision_threshold, features = detection_result
    elif len(detection_result) >= 6:
        is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score = detection_result[:6]
    else:
        is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score = detection_result
    
    ip = str(auth_data.get('ip', ''))
    
    # Use risk_score directly (realtime mode processes each log independently)
    risk_score = float(risk_score) if risk_score is not None else 0.0
    
    # Reconstruct Wazuh format output
    if wazuh_entry:
        # Use original Wazuh entry and add risk_score
        alert = wazuh_entry.copy()
        alert['risk_score'] = risk_score
        # Ensure password is in data object (Wazuh requires it)
        if 'data' in alert and isinstance(alert['data'], dict):
            if 'password' not in alert['data']:
                alert['data']['password'] = auth_data.get('password', '')
    else:
        # Fallback: construct Wazuh format from available data
        # Extract agent info from auth_data or use defaults
        agent_ip = auth_data.get('ip', '127.0.0.1')
        
        # Build full_log JSON string
        full_log_data = {
            'timestamp': auth_data.get('timestamp', ''),
            'username': auth_data.get('username', ''),
            'status_code': auth_data.get('status_code', 0),
            'ip': auth_data.get('ip', ''),
            'password': auth_data.get('password', '')
        }
        full_log_str = json.dumps(full_log_data, ensure_ascii=False)
        
        # Build data object (password included - Wazuh requires it)
        data_obj = {
            'timestamp': auth_data.get('timestamp', ''),
            'username': auth_data.get('username', ''),
            'status_code': str(auth_data.get('status_code', 0)),
            'ip': auth_data.get('ip', ''),
            'password': auth_data.get('password', '')
        }
        
        alert = {
            'timestamp': auth_data.get('timestamp', datetime.now().isoformat()),
            'agent': {
                'id': '001',
                'name': 'web-server',
                'ip': agent_ip
            },
            'manager': {
                'name': 'Wazuh'
            },
            'id': f"{int(time.time() * 1000)}.{int(time.time() * 1000000) % 100000000}",
            'full_log': full_log_str,
            'decoder': {
                'name': 'json'
            },
            'data': data_obj,
            'location': '/opt/ai-bruteforce/brute.log',
            'risk_score': risk_score
        }
    
    # Output file path - CHUẨN cho Wazuh SIEM
    alert_file = '/var/ossec/logs/brute.log'
    alert_dir = os.path.dirname(alert_file)
    
    # Ensure directory exists
    if alert_dir:
        try:
            os.makedirs(alert_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"❌ Failed to create output directory {alert_dir}: {e}")
            return
    
    # Write alert (only called when is_bruteforce is True)
    try:
        with open(alert_file, 'a', encoding='utf-8') as f:
            alert_json = json.dumps(alert, ensure_ascii=False, default=str) + '\n'
            f.write(alert_json)
            f.flush()  # Ensure immediate write
            logger.debug(f"✅ Alert written to {alert_file}")
    except PermissionError:
        logger.error(f"❌ NO WRITE PERMISSION: {alert_file}")
        logger.error("Please check file permissions for /var/ossec/logs/")
    except Exception as e:
        logger.error(f"❌ Error writing alert to {alert_file}: {e}")
        logger.error(traceback.format_exc())


def scan_existing_logs(log_file: str, detector: OptimizedBruteForceDetector):
    """
    [DEPRECATED] Scan existing logs in file (initial scan) - STREAMING MODE
    Writes alerts immediately when detected, no need to wait for all logs to be processed
    
    NOTE: This function is not used in realtime mode. Kept for backward compatibility.
    
    Args:
        log_file: Path to log file
        detector: Trained detector instance
    """
    global last_position
    processed_lines = set()  # Local variable for this function
    ip_max_risk_score = {}  # Local variable for this function
    
    if not os.path.exists(log_file):
        logger.warning(f"Log file not found: {log_file}")
        return
    
    logger.info(f"📖 Scanning existing logs in {log_file} (streaming mode - alerts written immediately)...")
    
    try:
        line_count = 0
        processed_count = 0
        detected_count = 0
        
        # Track max risk_score per IP as we process (for potential future use)
        ip_max_risk_score_local = {}  # Local tracking during scan
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line_count += 1
                line_hash = hash(line.strip())
                
                # Skip if already processed
                if line_hash in processed_lines:
                    continue
                
                # Parse log
                parse_result = parse_wazuh_log(line)
                if not parse_result:
                    continue
                
                auth_data, wazuh_entry = parse_result
                ip = auth_data.get('ip', '')
                
                # Convert to detector format
                log_entry = convert_to_detector_format(auth_data)
                
                # Detect
                try:
                    detect_start_time = time.time()
                    rule_flags = get_rule_flags()
                    detection_result = detector.predict_single(log_entry, threshold=DETECTION_THRESHOLD, rule_flags=rule_flags)
                    detect_end_time = time.time()
                    detect_duration_ms = (detect_end_time - detect_start_time) * 1000
                    
                    # Unpack result
                    if len(detection_result) >= 6:
                        is_bruteforce = detection_result[0]
                        risk_score = detection_result[5] if len(detection_result) > 5 else 0.0
                    else:
                        is_bruteforce = False
                        risk_score = 0.0
                    
                    # Log detailed information for ALL entries (including non-violations)
                    log_detection_details(auth_data, detection_result, detect_duration_ms)
                    
                    # STREAMING: Write alert immediately if bruteforce detected
                    if is_bruteforce and ip:
                        # Track max risk_score per IP
                        current_risk = float(risk_score) if risk_score is not None else 0.0
                        if ip not in ip_max_risk_score_local:
                            ip_max_risk_score_local[ip] = current_risk
                        else:
                            ip_max_risk_score_local[ip] = max(ip_max_risk_score_local[ip], current_risk)
                        
                        # Update global max risk_score
                        if ip not in ip_max_risk_score:
                            ip_max_risk_score[ip] = current_risk
                        else:
                            ip_max_risk_score[ip] = max(ip_max_risk_score[ip], current_risk)
                        
                        # Update detection_result with current max risk_score for this IP
                        # This ensures all alerts for same IP use the max risk_score found so far
                        if len(detection_result) >= 9:
                            detection_result = (
                                detection_result[0],  # is_bruteforce
                                detection_result[1],  # normalized_score
                                detection_result[2],  # patterns
                                detection_result[3],  # confidence
                                detection_result[4],  # threat_level
                                ip_max_risk_score[ip],  # risk_score (max so far)
                                detection_result[6],  # raw_anomaly_score
                                detection_result[7],  # decision_threshold
                                detection_result[8]   # features
                            )
                        elif len(detection_result) >= 6:
                            detection_result = (
                                detection_result[0],  # is_bruteforce
                                detection_result[1],  # normalized_score
                                detection_result[2],  # patterns
                                detection_result[3],  # confidence
                                detection_result[4],  # threat_level
                                ip_max_risk_score[ip]   # risk_score (max so far)
                            )
                        
                        # Write alert immediately (streaming)
                        write_alert(log_entry, detection_result, auth_data, wazuh_entry)
                        detected_count += 1
                        
                        # Progress update every 100 detections
                        if detected_count % 100 == 0:
                            logger.info(f"📊 Progress: {processed_count}/{line_count} processed, {detected_count} alerts written")
                    
                    processed_lines.add(line_hash)
                    processed_count += 1
                    
                    # Progress update every 10000 lines
                    if processed_count % 10000 == 0:
                        logger.info(f"📊 Progress: {processed_count} lines processed, {detected_count} alerts written")
                    
                except Exception as e:
                    logger.error(f"Error in detection: {e}")
                    continue
        
        # Update last position (file is already closed, so we'll set it to end of file)
        # This is approximate, but sufficient for tracking
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                f.seek(0, 2)  # Seek to end
                last_position = f.tell()
        except Exception:
            pass
        
        logger.info(f"✅ Initial scan completed:")
        logger.info(f"   - Total lines: {line_count}")
        logger.info(f"   - Processed: {processed_count}")
        logger.info(f"   - Detected: {detected_count} (alerts written immediately)")
            
    except Exception as e:
        logger.error(f"Error scanning existing logs: {e}")
        traceback.print_exc()


def read_new_logs_from_position(log_file: str, start_position: int) -> tuple:
    """
    Read only NEW logs from a specific file position (tail-like)
    Không đọc lại toàn bộ file, chỉ đọc từ vị trí cuối cùng
    
    Args:
        log_file: Path to log file
        start_position: File position to start reading from
    
    Returns:
        Tuple: (logs_list, new_position)
        - logs_list: List of tuples [(auth_data, wazuh_entry, log_timestamp), ...]
        - new_position: New file position after reading
    """
    logs = []
    new_position = start_position
    
    if not os.path.exists(log_file):
        return logs, new_position
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            # Seek to last known position
            f.seek(start_position)
            
            # Read only new lines
            for line in f:
                if not line.strip():
                    continue
                
                # Parse log
                parse_result = parse_wazuh_log(line)
                if not parse_result:
                    continue
                
                auth_data, wazuh_entry = parse_result
                
                # Parse timestamp để lưu vào deque
                timestamp_str = auth_data.get('timestamp', '')
                if not timestamp_str:
                    continue
                
                try:
                    from datetime import datetime
                    if '+' in timestamp_str or timestamp_str.endswith('Z'):
                        time_str_clean = timestamp_str.replace('+0700', '+07:00').replace('+0000', '+00:00')
                        dt = datetime.fromisoformat(time_str_clean.replace('Z', '+00:00'))
                    else:
                        dt = datetime.fromisoformat(timestamp_str)
                    log_timestamp = dt.timestamp()
                    
                    # Store with timestamp for deque cleanup
                    logs.append((auth_data, wazuh_entry, log_timestamp))
                except (ValueError, AttributeError):
                    continue
            
            # Update position
            new_position = f.tell()
            
    except Exception as e:
        logger.error(f"Error reading new logs: {e}")
    
    return logs, new_position


def detect_bruteforce_realtime(log_file: str, detector: OptimizedBruteForceDetector):
    """
    Real-time brute-force detection - Xử lý ngay khi có log mới
    - Đọc log mới từ vị trí cuối cùng (tail -f style)
    - Detect ngay lập tức khi có log mới
    - Chỉ ghi các log phát hiện brute-force vào output file
    
    Args:
        log_file: Path to log file (input: /opt/ai-bruteforce/brute.log)
        detector: Trained detector instance
    """
    global running, last_position
    
    # Validate input log file exists and readable
    if not os.path.exists(log_file):
        logger.error(f"❌ INPUT LOG FILE NOT FOUND: {log_file}")
        logger.error("Please ensure the input log file exists")
        return
    
    if not os.access(log_file, os.R_OK):
        logger.error(f"❌ NO READ PERMISSION: {log_file}")
        logger.error("Please check file permissions")
        return
    
    OUTPUT_ALERT_FILE = '/var/ossec/logs/brute.log'
    
    logger.info(f"👀 Real-time monitoring:")
    logger.info(f"   📥 INPUT:  {log_file}")
    logger.info(f"   📤 OUTPUT: {OUTPUT_ALERT_FILE}")
    logger.info(f"   - ✅ REAL-TIME: Detect ngay khi có log mới")
    logger.info(f"   - ✅ CHỈ GHI: Các log phát hiện brute-force vào {OUTPUT_ALERT_FILE}")
    logger.info("Press Ctrl+C to stop")
    
    # Initialize file position (bắt đầu từ cuối file = chỉ đọc log mới)
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            f.seek(0, 2)  # Seek to end
            last_position = f.tell()
        logger.info(f"📌 Starting position: {last_position} bytes (chỉ đọc log mới từ đây)")
    except Exception as e:
        logger.error(f"❌ Error reading input log file: {e}")
        return
    
    # Track processed alerts to avoid duplicates
    processed_alert_logs = set()
    last_cleanup_time = time.time()
    CLEANUP_INTERVAL = 600  # Cleanup every 10 minutes
    
    try:
        while running:
            current_time = time.time()
            
            # Cleanup processed_alert_logs định kỳ để tránh memory leak
            if current_time - last_cleanup_time > CLEANUP_INTERVAL or len(processed_alert_logs) > 10000:
                old_size = len(processed_alert_logs)
                processed_alert_logs.clear()
                last_cleanup_time = current_time
                logger.debug(f"🧹 Cleaned up processed_alert_logs (removed {old_size} entries)")
            
            # Đọc log mới từ vị trí cuối cùng
            new_logs, last_position = read_new_logs_from_position(log_file, last_position)
            
            # Xử lý từng log mới ngay lập tức
            if new_logs:
                logger.debug(f"📥 Read {len(new_logs)} new log entries")
                
                for auth_data, wazuh_entry, log_timestamp in new_logs:
                    try:
                        # Convert to detector format
                        log_entry = convert_to_detector_format(auth_data)
                        
                        # Detect brute-force
                        detect_start_time = time.time()
                        rule_flags = get_rule_flags()
                        detection_result = detector.predict_single(log_entry, threshold=DETECTION_THRESHOLD, rule_flags=rule_flags)
                        detect_end_time = time.time()
                        detect_duration_ms = (detect_end_time - detect_start_time) * 1000
                        
                        # Unpack result - Always expect extended tuple format (9 elements)
                        if len(detection_result) >= 9:
                            is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score, raw_anomaly_score, decision_threshold, features = detection_result
                        elif len(detection_result) >= 6:
                            # Fallback for old format (should not happen with current code)
                            is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score = detection_result[:6]
                            raw_anomaly_score = None
                            decision_threshold = DETECTION_THRESHOLD if DETECTION_THRESHOLD is not None else 0.091730
                            features = {}
                        else:
                            # Invalid format - log error and skip
                            logger.error(f"Invalid detection_result format: expected 9 elements, got {len(detection_result)}")
                            continue
                        
                        # CHỈ GHI các log phát hiện brute-force
                        if is_bruteforce:
                            ip = auth_data.get('ip', '')
                            
                            # Tạo unique key cho log này để tránh ghi trùng
                            log_key = (
                                ip,
                                auth_data.get('timestamp', ''),
                                auth_data.get('username', ''),
                                auth_data.get('password', '')
                            )
                            
                            # Chỉ ghi alert nếu chưa ghi trước đó
                            if log_key not in processed_alert_logs:
                                processed_alert_logs.add(log_key)
                                
                                # Log detection details
                                log_detection_details(auth_data, detection_result, detect_duration_ms)
                                
                                # Write alert to output file
                                write_alert(log_entry, detection_result, auth_data, wazuh_entry)
                                
                                # Log warning
                                logger.warning(f"🚨 BRUTE-FORCE DETECTED: IP={ip}, User={auth_data.get('username', 'unknown')}, Threat={threat_level}, Risk={risk_score:.2f}, Patterns={patterns}")
                        
                    except Exception as e:
                        logger.error(f"Error processing log entry: {e}")
                        logger.debug(traceback.format_exc())
                        continue
            
            # Sleep ngắn để tránh CPU 100% (0.1s = 100ms)
            time.sleep(0.1)
                
    except KeyboardInterrupt:
        # Already handled by signal_handler
        pass
    except Exception as e:
        logger.error(f"Error in real-time detection: {e}")
        traceback.print_exc()


def detect_bruteforce_window_based(log_file: str, detector: OptimizedBruteForceDetector):
    """
    [DEPRECATED] Window-based brute-force detection - OPTIMIZED với deque
    - Chỉ đọc log mới từ vị trí cuối cùng (tail-like)
    - Lưu logs trong 60 giây gần nhất vào deque
    - Tự động xóa logs cũ hơn 60 giây
    - Chỉ kiểm tra brute-force trong deque
    
    NOTE: This function is not used in realtime mode. Use detect_bruteforce_realtime() instead.
    
    Args:
        log_file: Path to log file
        detector: Trained detector instance
    """
    global running, last_position
    
    if not os.path.exists(log_file):
        logger.error(f"Log file not found: {log_file}")
        return
    
    logger.info(f"👀 Window-based monitoring: {log_file}")
    logger.info(f"   - Window interval: {WINDOW_INTERVAL_SECONDS} seconds")
    logger.info(f"   - Feature window: {FEATURE_WINDOW_SECONDS} seconds")
    logger.info("   - ✅ OPTIMIZED: Chỉ đọc log mới, sử dụng deque cho window 60s")
    logger.info("Press Ctrl+C to stop")
    
    # Initialize file position (bắt đầu từ cuối file = chỉ đọc log mới)
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            f.seek(0, 2)  # Seek to end
            last_position = f.tell()
        logger.info(f"📌 Starting position: {last_position} (chỉ đọc log mới từ đây)")
    except Exception:
        last_position = 0
    
    # Deque để lưu logs trong 60 giây gần nhất
    # Format: deque([(auth_data, wazuh_entry, timestamp), ...])
    logs_deque = deque()
    
    last_processed_time = {}  # Track last processed time per IP to avoid duplicate alerts
    processed_alert_logs = set()  # Local variable for this function
    ip_max_risk_score = {}  # Local variable for this function
    last_cleanup_time = time.time()  # Track last cleanup time for processed_alert_logs
    CLEANUP_INTERVAL = 600  # Cleanup processed_alert_logs every 10 minutes
    
    try:
        while running:
            window_start = time.time()
            current_time = time.time()
            cutoff_time = current_time - FEATURE_WINDOW_SECONDS
            
            # Cleanup processed_alert_logs định kỳ để tránh memory leak
            if current_time - last_cleanup_time > CLEANUP_INTERVAL or len(processed_alert_logs) > 10000:
                old_size = len(processed_alert_logs)
                # Xóa toàn bộ và bắt đầu lại (logs cũ đã không còn trong window nữa)
                processed_alert_logs.clear()
                last_cleanup_time = current_time
                logger.debug(f"🧹 Cleaned up processed_alert_logs (removed {old_size} entries)")
            
            # 1. Đọc chỉ LOG MỚI từ vị trí cuối cùng
            new_logs, last_position = read_new_logs_from_position(log_file, last_position)
            
            # 2. Thêm log mới vào deque
            if new_logs:
                for auth_data, wazuh_entry, log_timestamp in new_logs:
                    logs_deque.append((auth_data, wazuh_entry, log_timestamp))
                logger.debug(f"📥 Added {len(new_logs)} new logs to deque (total: {len(logs_deque)})")
            
            # 3. Xóa logs cũ hơn 60 giây từ đầu deque
            while logs_deque and logs_deque[0][2] < cutoff_time:
                logs_deque.popleft()
            
            if not logs_deque:
                # No logs in window, wait for next interval
                time.sleep(WINDOW_INTERVAL_SECONDS)
                continue
            
            # 4. Lọc logs trong window (double-check, phòng trường hợp có logs ngoài window)
            logs_in_window = [
                (auth_data, wazuh_entry) 
                for auth_data, wazuh_entry, log_timestamp in logs_deque
                if log_timestamp >= cutoff_time
            ]
            
            if not logs_in_window:
                time.sleep(WINDOW_INTERVAL_SECONDS)
                continue
            
            # 5. Group logs by IP
            logs_by_ip = {}
            for auth_data, wazuh_entry in logs_in_window:
                ip = auth_data.get('ip', '')
                if not ip:
                    continue
                if ip not in logs_by_ip:
                    logs_by_ip[ip] = []
                logs_by_ip[ip].append((auth_data, wazuh_entry))
            
            logger.debug(f"📊 Processing window: {len(logs_in_window)} logs from {len(logs_by_ip)} IPs (deque size: {len(logs_deque)})")
            
            # Process each IP
            for ip, ip_logs in logs_by_ip.items():
                try:
                    # IMPORTANT: Clear tracker for this IP first to ensure clean state
                    # Then track all logs in window to build proper feature state
                    # This ensures features like failed_logins_1min, unique_passwords_tried are calculated correctly
                    detector.bruteforce_tracker.clear_ip(ip)
                    
                    # Track all logs in window for this IP
                    for auth_data, wazuh_entry in ip_logs:
                        log_entry_temp = convert_to_detector_format(auth_data)
                        # Track this log entry (this populates the tracker with all logs in window)
                        # We don't predict yet, just track
                        detector.extract_bruteforce_features(log_entry_temp)
                    
                    # Now use the most recent log entry as representative for prediction
                    # Features will be calculated from tracker which now has all logs in window
                    latest_log, latest_wazuh_entry = max(ip_logs, key=lambda x: x[0].get('timestamp', ''))
                    log_entry = convert_to_detector_format(latest_log)
                    
                    # Predict (features are now calculated from full window state in tracker)
                    detect_start_time = time.time()
                    rule_flags = get_rule_flags()
                    detection_result = detector.predict_single(log_entry, threshold=DETECTION_THRESHOLD, rule_flags=rule_flags)
                    detect_end_time = time.time()
                    detect_duration_ms = (detect_end_time - detect_start_time) * 1000
                    
                    # Unpack result
                    if len(detection_result) >= 9:
                        is_bruteforce, normalized_score, patterns, confidence, threat_level, risk_score, raw_anomaly_score, decision_threshold, features = detection_result
                    elif len(detection_result) >= 6:
                        is_bruteforce = detection_result[0]
                        raw_anomaly_score = None
                        decision_threshold = DETECTION_THRESHOLD or 0.091730
                        features = {}
                    else:
                        is_bruteforce = False
                        raw_anomaly_score = None
                        decision_threshold = DETECTION_THRESHOLD or 0.091730
                        features = {}
                    
                    # Log features for debugging (only for detected cases or first few)
                    if is_bruteforce or ip not in last_processed_time:
                        # Format raw_score safely
                        raw_score_str = f"{raw_anomaly_score:.6f}" if raw_anomaly_score is not None else "N/A"
                        threshold_str = f"{decision_threshold:.6f}" if decision_threshold is not None else "N/A"
                        
                        logger.info(f"🔍 Features for IP={ip}: "
                                  f"failed_login_rate={features.get('failed_login_rate', 0):.2f}, "
                                  f"unique_usernames={features.get('unique_usernames_tried', 0)}, "
                                  f"unique_passwords={features.get('unique_passwords_tried', 0)}, "
                                  f"failed_logins_1min={features.get('failed_logins_1min', 0)}, "
                                  f"time_between={features.get('time_between_attempts', 0):.2f}s, "
                                  f"spam_user={features.get('spamming_username', 0)}, "
                                  f"spam_pass={features.get('spamming_password', 0)}, "
                                  f"logs_in_window={len(ip_logs)}, "
                                  f"raw_score={raw_score_str}, "
                                  f"threshold={threshold_str}")
                    
                    # Only alert if not recently alerted for this IP (avoid spam)
                    last_alert_time = last_processed_time.get(ip, 0)
                    time_since_last_alert = current_time - last_alert_time
                    
                    if is_bruteforce:
                        # Log detection details
                        log_detection_details(latest_log, detection_result, detect_duration_ms)
                        
                        # Collect all violation logs and their detection results to find max risk_score
                        violation_logs = []
                        max_risk_score = 0.0
                        
                        # Clear tracker and re-track for each log to get accurate individual predictions
                        for auth_data, wazuh_entry in ip_logs:
                            # Clear and re-track up to this log
                            detector.bruteforce_tracker.clear_ip(ip)
                            for auth_data_temp, _ in ip_logs:
                                if auth_data_temp.get('timestamp', '') <= auth_data.get('timestamp', ''):
                                    log_entry_temp = convert_to_detector_format(auth_data_temp)
                                    detector.extract_bruteforce_features(log_entry_temp)
                            
                            # Predict this log
                            log_entry_temp = convert_to_detector_format(auth_data)
                            rule_flags = get_rule_flags()
                            detect_result_temp = detector.predict_single(log_entry_temp, threshold=DETECTION_THRESHOLD, rule_flags=rule_flags)
                            
                            if len(detect_result_temp) >= 6 and detect_result_temp[0]:  # is_bruteforce
                                risk_score_temp = detect_result_temp[5] if len(detect_result_temp) > 5 else 0.0
                                max_risk_score = max(max_risk_score, float(risk_score_temp) if risk_score_temp is not None else 0.0)
                                violation_logs.append((log_entry_temp, detect_result_temp, auth_data, wazuh_entry))
                        
                        # Update global max risk_score for this IP
                        if ip not in ip_max_risk_score:
                            ip_max_risk_score[ip] = max_risk_score
                        else:
                            ip_max_risk_score[ip] = max(ip_max_risk_score[ip], max_risk_score)
                        
                        # Write alerts for all violation logs with max risk_score (only if not recently alerted)
                        if time_since_last_alert > 60:  # Alert at most once per minute per IP
                            new_violation_logs = []
                            for log_entry_viol, detect_result_viol, auth_data_viol, wazuh_entry_viol in violation_logs:
                                # Tạo unique key cho log này để tránh ghi trùng
                                log_key = (
                                    ip,
                                    auth_data_viol.get('timestamp', ''),
                                    auth_data_viol.get('username', ''),
                                    auth_data_viol.get('password', '')
                                )
                                
                                # Chỉ ghi alert nếu chưa ghi trước đó
                                if log_key not in processed_alert_logs:
                                    processed_alert_logs.add(log_key)
                                    new_violation_logs.append((log_entry_viol, detect_result_viol, auth_data_viol, wazuh_entry_viol))
                            
                            # Chỉ ghi alerts mới (chưa được ghi trước đó)
                            if new_violation_logs:
                                for log_entry_viol, detect_result_viol, auth_data_viol, wazuh_entry_viol in new_violation_logs:
                                    # Update detection_result with max risk_score
                                    if len(detect_result_viol) >= 9:
                                        detect_result_viol = (
                                            detect_result_viol[0],  # is_bruteforce
                                            detect_result_viol[1],  # normalized_score
                                            detect_result_viol[2],  # patterns
                                            detect_result_viol[3],  # confidence
                                            detect_result_viol[4],  # threat_level
                                            ip_max_risk_score[ip],  # risk_score (max)
                                            detect_result_viol[6],  # raw_anomaly_score
                                            detect_result_viol[7],  # decision_threshold
                                            detect_result_viol[8]   # features
                                        )
                                    elif len(detect_result_viol) >= 6:
                                        detect_result_viol = (
                                            detect_result_viol[0],  # is_bruteforce
                                            detect_result_viol[1],  # normalized_score
                                            detect_result_viol[2],  # patterns
                                            detect_result_viol[3],  # confidence
                                            detect_result_viol[4],  # threat_level
                                            ip_max_risk_score[ip]   # risk_score (max)
                                        )
                                    write_alert(log_entry_viol, detect_result_viol, auth_data_viol, wazuh_entry_viol)
                                last_processed_time[ip] = current_time
                                logger.warning(f"🚨 BRUTE-FORCE detected for IP={ip} (window-based detection), {len(new_violation_logs)} NEW violation logs (skipped {len(violation_logs) - len(new_violation_logs)} duplicates), max_risk_score={ip_max_risk_score[ip]:.2f}")
                    else:
                        # Log normal entries at DEBUG level to reduce noise
                        logger.debug(f"✓ Normal: IP={ip}, logs_in_window={len(ip_logs)}")
                    
                except Exception as e:
                    logger.error(f"Error processing IP {ip}: {e}")
                    continue
            
            # Wait for next window interval
            elapsed = time.time() - window_start
            sleep_time = max(0, WINDOW_INTERVAL_SECONDS - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)
                
    except KeyboardInterrupt:
        # Already handled by signal_handler
        pass
    except Exception as e:
        logger.error(f"Error in window-based detection: {e}")
        traceback.print_exc()


def main():
    """Main function"""
    global detector, running
    
    # Setup signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Configuration - PATHS CHUẨN
    INPUT_LOG_FILE = '/opt/ai-bruteforce/brute.log'
    OUTPUT_ALERT_FILE = '/var/ossec/logs/brute.log'
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models/optimized_bruteforce_detector.pkl')
    
    logger.info("=" * 70)
    logger.info("🚀 Real-time Brute-Force Detection System")
    logger.info("=" * 70)
    logger.info(f"📥 INPUT LOG:  {INPUT_LOG_FILE}")
    logger.info(f"📤 OUTPUT LOG: {OUTPUT_ALERT_FILE}")
    logger.info(f"🤖 MODEL:      {model_path}")
    
    # Validate input log file
    if not os.path.exists(INPUT_LOG_FILE):
        logger.error(f"❌ INPUT LOG FILE NOT FOUND: {INPUT_LOG_FILE}")
        logger.error("Please create the input log file or check the path")
        logger.error("Creating directory and file...")
        os.makedirs(os.path.dirname(INPUT_LOG_FILE), exist_ok=True)
        with open(INPUT_LOG_FILE, 'w') as f:
            pass
        logger.info(f"✅ Created input log file: {INPUT_LOG_FILE}")
    
    # Validate output directory
    output_dir = os.path.dirname(OUTPUT_ALERT_FILE)
    if not os.path.exists(output_dir):
        logger.warning(f"⚠️  OUTPUT DIRECTORY NOT FOUND: {output_dir}")
        logger.info("Creating output directory...")
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"✅ Created output directory: {output_dir}")
    
    # Check write permission for output file
    try:
        with open(OUTPUT_ALERT_FILE, 'a') as f:
            pass
        logger.info(f"✅ Output file writable: {OUTPUT_ALERT_FILE}")
    except PermissionError:
        logger.error(f"❌ NO WRITE PERMISSION: {OUTPUT_ALERT_FILE}")
        logger.error("Please check file permissions")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Error checking output file: {e}")
        sys.exit(1)
    if DETECTION_THRESHOLD is None:
        logger.info(f"Detection threshold: Auto (using model default: 50th percentile)")
    else:
        logger.info(f"Detection threshold: {DETECTION_THRESHOLD}")
    logger.info("=" * 70)
    logger.info("📊 Rule Configuration:")
    logger.info(f"   - Rule 1 (Username Enumeration): {'ENABLED' if RULE_1_ENABLED else 'DISABLED'}")
    logger.info(f"   - Rule 2 (Password Spraying): {'ENABLED' if RULE_2_ENABLED else 'DISABLED'}")
    logger.info(f"   - Rule 3 (High Request Rate): {'ENABLED' if RULE_3_ENABLED else 'DISABLED'}")
    logger.info(f"   - Rule 4 (False Positive Filter): {'ENABLED' if RULE_4_ENABLED else 'DISABLED'}")
    logger.info("=" * 70)
    logger.info("📊 LOGGING MODE:")
    logger.info(f"   - 🚨 = Brute-force detected (WARNING level) - Ghi vào {OUTPUT_ALERT_FILE}")
    logger.info("   - DEBUG = Normal entry (chỉ log khi có brute-force)")
    logger.info("=" * 70)
    logger.info("⚠️  NOTE: Real-time detection - Xử lý ngay khi có log mới")
    logger.info(f"⚠️  NOTE: Chỉ ghi các log phát hiện brute-force vào {OUTPUT_ALERT_FILE}")
    logger.info("=" * 70)
    
    # Check if model exists
    if not os.path.exists(model_path):
        logger.error(f"❌ Model file not found: {model_path}")
        logger.error("Please train the model first using: python optimized_bruteforce_detector.py")
        sys.exit(1)
    
    # Load model
    try:
        logger.info("📦 Loading trained model...")
        detector = OptimizedBruteForceDetector()
        detector.load_model(model_path)
        logger.info("✅ Model loaded successfully!")
    except Exception as e:
        logger.error(f"❌ Error loading model: {e}")
        traceback.print_exc()
        sys.exit(1)
    
    # Real-time monitoring - Xử lý ngay khi có log mới
    try:
        detect_bruteforce_realtime(INPUT_LOG_FILE, detector)
    except Exception as e:
        logger.error(f"Error in real-time monitoring: {e}")
        traceback.print_exc()
    
    logger.info("👋 Shutdown complete. Goodbye!")


if __name__ == "__main__":
    main()


