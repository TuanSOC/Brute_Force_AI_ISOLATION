#!/usr/bin/env python3
"""
Optimized Brute-Force Detector – mô-đun lõi AI không giám sát (Isolation Forest)

Chức năng chính:
- Trích xuất đặc trưng tối ưu từ log web (feature engineering hướng Brute-Force)
- Huấn luyện IsolationForest trên dữ liệu sạch (unsupervised)
- Dự đoán đơn lẻ hoặc theo lô, trả điểm bất thường 0–1
- Hybrid detection: Rule-based (Priority 1) + AI-based (Bước 3) để vừa nhạy vừa ít false positive

Logic detection:
- Bước 1: Rule-based detection (4 rules) - phát hiện patterns rõ ràng
- Bước 3: AI-based detection (Isolation Forest) - phát hiện patterns phức tạp
- Rule 4: False positive filter - lọc các trường hợp AI phát hiện nhưng quá ít log
"""

import pandas as pd
import joblib
import json
import os
import sys
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import re
import logging
import math
import urllib.parse
import ipaddress as _ip
import numpy as np
from typing import Optional
from bruteforce_tracker import BruteForceTracker

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def url_decode_safe(s: str, max_passes: int = 3) -> str:
    """URL decode với multi-pass (tối đa max_passes lần)"""
    if not s:
        return s
    result = s
    for _ in range(max_passes):
        try:
            decoded = urllib.parse.unquote_plus(result)
            if decoded == result:
                break
            result = decoded
        except Exception:
            break
    return result


def convert_normal_log_to_detector_format(normal_log_entry: dict) -> dict:
    """
    Convert normal.log format to detector format
    
    Input format (normal.log):
    {
        "timestamp": "2025-09-29T19:55:00.000+0700",
        "username": "ian",
        "password": "database",
        "status_code": 320,
        "ip": "100.213.214.125"
    }
    
    Output format (detector):
    {
        "remote_ip": "100.213.214.125",
        "uri": "/login",
        "method": "POST",
        "status": 320,
        "payload": "username=ian&password=database",
        "query_string": "",
        "time": "2025-09-29T19:55:00.000+0700",
        ...
    }
    """
    # Extract fields from normal log
    timestamp = normal_log_entry.get('timestamp', '')
    username = normal_log_entry.get('username', '')
    password = normal_log_entry.get('password', '')
    status_code = normal_log_entry.get('status_code', 0)
    ip = normal_log_entry.get('ip', '')
    
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
        'uri': '/login',  # Default login endpoint
        'method': 'POST',  # Login usually uses POST
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


def extract_credentials_from_payload(payload: str, query_string: str = '') -> tuple:
    """
    Extract username and password from payload/query string
    
    Returns:
        (username, password) tuple
    """
    username = None
    password = None
    
    # Common field names for username
    username_fields = ['username', 'user', 'email', 'login', 'account', 'userid', 'user_id']
    # Common field names for password
    password_fields = ['password', 'pass', 'pwd', 'passwd', 'secret']
    
    # Decode payload and query string
    decoded_payload = url_decode_safe(payload)
    decoded_query = url_decode_safe(query_string)
    
    # Search in payload
    for field in username_fields:
        pattern = rf'{field}[=:]\s*([^&\s]+)'
        match = re.search(pattern, decoded_payload, re.IGNORECASE)
        if match:
            username = match.group(1).strip()
            break
    
    for field in password_fields:
        pattern = rf'{field}[=:]\s*([^&\s]+)'
        match = re.search(pattern, decoded_payload, re.IGNORECASE)
        if match:
            password = match.group(1).strip()
            break
    
    # Search in query string if not found
    if not username:
        for field in username_fields:
            pattern = rf'{field}[=:]\s*([^&\s]+)'
            match = re.search(pattern, decoded_query, re.IGNORECASE)
            if match:
                username = match.group(1).strip()
                break
    
    if not password:
        for field in password_fields:
            pattern = rf'{field}[=:]\s*([^&\s]+)'
            match = re.search(pattern, decoded_query, re.IGNORECASE)
            if match:
                password = match.group(1).strip()
                break
    
    return username, password


class OptimizedBruteForceDetector:
    """Bao gói toàn bộ pipeline: features → scale → IsolationForest.
    
    Tham số khởi tạo cho phép tinh chỉnh tốc độ/độ nhạy:
    - contamination: ước lượng tỷ lệ outlier trong tập sạch để IF tự hiệu chỉnh
    - n_estimators, max_features: kiểm soát số cây và số đặc trưng mỗi cây
    - random_state: tái lập
    - n_jobs: số core dùng khi train/predict
    """

    def __init__(self, contamination='auto', random_state=42, n_estimators=300, 
                 max_features=1.0, n_jobs=-1):
        self.contamination = contamination
        self.random_state = random_state
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=n_estimators,
            max_samples='auto',
            max_features=max_features,
            bootstrap=False,
            n_jobs=n_jobs
        )
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_trained = False
        self.feature_names = []
        self.version = "1.0.0"
        self.decision_threshold = None
        
        # Initialize tracker
        self.bruteforce_tracker = BruteForceTracker()
    
    def extract_bruteforce_features(self, log_entry):
        """
        Trích xuất features brute-force cho 1 log_entry.
        
        Features được capped để tránh outlier ảnh hưởng đến model:
        - failed_login_rate: cap at 0.0-1.0 (0%-100%)
        - unique_usernames_tried: cap at 5
        - unique_passwords_tried: cap at 10
        - time_between_attempts: cap at 0-60 seconds
        - failed_logins_1min: cap at 10
        - spamming_username: cap at 100
        - spamming_password: cap at 100

        Yêu cầu tối ưu:
        - Đảm bảo tracker dùng đúng thời gian thực (nếu BruteForceTracker hỗ trợ timestamp).
        - Không ép cứng rate khi chỉ có 0–1 request nếu không cần thiết.
        """
        features = {}

        # 1. Basic
        status = int(log_entry.get('status', 0) or 0)
        features['status'] = status

        # 2. Credentials
        payload = log_entry.get('payload', '') or ''
        query_string = log_entry.get('query_string', '') or ''
        username, password = extract_credentials_from_payload(payload, query_string)

        remote_ip = log_entry.get('remote_ip', '') or ''

        # 3. Track request trong tracker
        # Parse timestamp từ log entry để dùng đúng thời gian thực
        timestamp = None
        time_str = log_entry.get('time', '') or log_entry.get('timestamp', '')
        if time_str:
            try:
                from datetime import datetime
                # Parse timestamp (format: "2025-01-01T00:00:00.000+0700" hoặc ISO format)
                if '+' in time_str or time_str.endswith('Z'):
                    # ISO format with timezone
                    time_str_clean = time_str.replace('+0700', '+07:00').replace('+0000', '+00:00')
                    dt = datetime.fromisoformat(time_str_clean.replace('Z', '+00:00'))
                else:
                    # ISO format without timezone
                    dt = datetime.fromisoformat(time_str)
                timestamp = dt.timestamp()
            except (ValueError, AttributeError):
                # Nếu không parse được, dùng None (sẽ dùng time.time())
                timestamp = None
        
        # 4. Metrics theo time window (dùng timestamp từ log entry)
        # Tính metrics TRƯỚC khi track request hiện tại để metrics phản ánh trạng thái trước request này
        current_time = timestamp if timestamp else None
        metrics_1min = self.bruteforce_tracker.get_metrics(remote_ip, time_window_seconds=60, current_time=current_time)
        metrics_5min = self.bruteforce_tracker.get_metrics(remote_ip, time_window_seconds=300, current_time=current_time)
        
        # Track request với timestamp từ log entry (SAU khi tính metrics)
        self.bruteforce_tracker.track_request(remote_ip, status, username, password, timestamp=timestamp)
        # metrics_1hour = self.bruteforce_tracker.get_metrics(remote_ip, time_window_seconds=3600)
        # (hiện chưa dùng trực tiếp)

        # 5. Rate-based
        requests_count_1min = metrics_1min.get('requests_count', 0) or 0
        # Apply capped for training features: 0.0 - 1.0 (0% - 100%)
        failed_rate = float(metrics_1min.get('failed_login_rate', 0.0) or 0.0)
        features['failed_login_rate'] = float(max(0.0, min(failed_rate, 1.0)))

        # 6. Pattern-based
        features['has_failed_login'] = 1 if status == 320 else 0
        # Check username enumeration: >5 usernames in 1 minute (dùng timestamp từ log entry)
        features['has_username_enumeration'] = 1 if self.bruteforce_tracker.get_username_enumeration(remote_ip, time_window_seconds=60, current_time=current_time) else 0

        if username:
            features['has_password_spraying'] = 1 if self.bruteforce_tracker.get_password_spraying(remote_ip, username, time_window_seconds=60, current_time=current_time) else 0
        else:
            features['has_password_spraying'] = 0

        # 7. Behavioral
        # Apply capped for training features
        features['unique_usernames_tried'] = int(min(metrics_1min.get('unique_usernames', 0) or 0, 5))   # Cap at 5
        features['unique_passwords_tried'] = int(min(metrics_1min.get('unique_passwords', 0) or 0, 10))  # Cap at 10

        if requests_count_1min > 1:
            time_between = 60.0 / requests_count_1min
        else:
            time_between = 60.0
        # Apply capped for training features: 0-60 seconds
        features['time_between_attempts'] = float(max(0.0, min(time_between, 60.0)))

        # Calculate time_between_score for risk calculation (not a feature itself)
        time_between_score = max(0.0, min(1.0, (60.0 - time_between) / 60.0))

        # 8. Spamming (1h toàn hệ thống) - dùng timestamp từ log entry
        spamming_username = 0
        spamming_password = 0
        if username:
            spamming_username = self.bruteforce_tracker.get_username_spamming_count(username, time_window_seconds=3600, current_time=current_time)
        if password:
            spamming_password = self.bruteforce_tracker.get_password_spamming_count(password, time_window_seconds=3600, current_time=current_time)

        # Apply capped for training features
        features['spamming_username'] = int(min(spamming_username or 0, 100))  # Cap at 100
        features['spamming_password'] = int(min(spamming_password or 0, 100))  # Cap at 100

        # 9. Failed logins 1 phút
        # Apply capped for training features
        features['failed_logins_1min'] = int(min(metrics_1min.get('failed_login_count', 0) or 0, 10))  # Cap at 10

        # 10. Risk score
        # Features đã được capped ở trên, nên dùng trực tiếp
        bruteforce_risk_score = (
            features['failed_login_rate'] * 15.0 +
            features['has_failed_login'] * 3.0 +
            features['has_username_enumeration'] * 20.0 +
            features['has_password_spraying'] * 15.0 +
            float(features['unique_usernames_tried']) * 1.0 +
            float(features['unique_passwords_tried']) * 1.0 +
            float(features['failed_logins_1min']) * 1.0 +
            time_between_score * 15.0 +
            float(features['spamming_username']) * 0.2 +
            float(features['spamming_password']) * 0.2
        )

        features['bruteforce_risk_score'] = float(bruteforce_risk_score)
        # Nếu không dùng log-scale, có thể bỏ dòng dưới:
        features['bruteforce_risk_score_log'] = math.log1p(bruteforce_risk_score)

        # Return features và metrics để dùng lại trong predict_single (tránh gọi get_metrics() lại)
        return features, metrics_1min, current_time

    def train(self, clean_logs):
        """
        Train Isolation Forest model theo workflow chuẩn
        
        Workflow:
        [1] Load CLEAN logs
        [2] Extract features từ mỗi log
        [3] Tạo DataFrame
        [4] CHỌN 7 FEATURES (KHÔNG bao gồm status, bruteforce_risk_score, và pattern-based features)
        [5] Standard Scaling (mean=0, std=1)
        [6] Train Isolation Forest (300 trees)
        [7] Tính percentiles từ training scores
        [8] Save model + metadata
        """
        logger.info("🚀 Training Optimized Brute-Force Detector...")
        logger.info("=" * 70)
        
        # [1] Load CLEAN logs
        logger.info(f"[1] Loaded {len(clean_logs)} CLEAN log entries")
        
        # [2] Extract features từ mỗi log
        logger.info("[2] Extracting features from each log entry...")
        features_list = []
        for log_entry in clean_logs:
            features, _, _ = self.extract_bruteforce_features(log_entry)
            features_list.append(features)
        logger.info(f"    ✅ Extracted features from {len(features_list)} logs")
        
        # [3] Tạo DataFrame (N rows × M columns)
        logger.info("[3] Creating DataFrame...")
        df = pd.DataFrame(features_list)
        logger.info(f"    ✅ DataFrame shape: {df.shape} (rows × columns)")
        
        # Encode categorical features (nếu có)
        categorical_features = ['method']
        for feature in categorical_features:
            if feature in df.columns:
                le = LabelEncoder()
                df[f'{feature}_encoded'] = le.fit_transform(df[feature].astype(str))
                self.label_encoders[feature] = le
        
        # [4] CHỌN 7 FEATURES ĐỂ TRAIN
        # LƯU Ý: KHÔNG bao gồm 'status', 'bruteforce_risk_score', và 3 pattern-based features
        # (has_failed_login, has_username_enumeration, has_password_spraying được giữ lại
        #  để dùng cho rule-based detection sau này, nhưng không dùng để train AI)
        logger.info("[4] Selecting 7 features for training (excluding 'status', 'bruteforce_risk_score', and pattern-based features)...")
        self.feature_names = [
            # Rate-based (1 feature)
            'failed_login_rate',
            # Behavioral (4 features)
            'unique_usernames_tried',
            'unique_passwords_tried',
            'time_between_attempts',
            'failed_logins_1min',
            # Spamming (2 features)
            'spamming_username',
            'spamming_password'
            # TỔNG CỘNG: 7 features
            # LOẠI BỎ: 'status', 'bruteforce_risk_score', 'requests_per_minute', 'requests_per_second'
            # LOẠI BỎ (nhưng vẫn extract để dùng sau): 'has_failed_login', 'has_username_enumeration', 'has_password_spraying'
        ]
        
        # Filter to existing columns
        self.feature_names = [f for f in self.feature_names if f in df.columns]
        
        if len(self.feature_names) != 7:
            missing = set(self.feature_names) - set(df.columns)
            if missing:
                logger.warning(f"⚠️  Missing features: {missing}")
            logger.warning(f"⚠️  Expected 7 features, got {len(self.feature_names)}")
        else:
            logger.info(f"    ✅ Selected {len(self.feature_names)} features: {self.feature_names}")
        
        # Select features và fill missing values
        X = df[self.feature_names].fillna(0)
        logger.info(f"    ✅ Feature matrix X shape: {X.shape} (samples × features)")
        
        # [5] Standard Scaling (mean=0, std=1)
        logger.info("[5] Standard Scaling features (mean=0, std=1)...")
        X_scaled = self.scaler.fit_transform(X)
        logger.info(f"    ✅ Scaled matrix X_scaled shape: {X_scaled.shape}")
        logger.info(f"    ✅ Scaler fitted: mean≈0, std≈1 for each feature")
        
        # [6] Train Isolation Forest
        logger.info("[6] Training Isolation Forest...")
        logger.info(f"    - n_estimators: {self.isolation_forest.n_estimators} trees")
        logger.info(f"    - max_features: {self.isolation_forest.max_features}")
        logger.info(f"    - contamination: {self.contamination}")
        logger.info("    - Building trees with random feature selection and random splits...")
        self.isolation_forest.fit(X_scaled)
        logger.info("    ✅ Isolation Forest trained successfully!")
        logger.info("    - Model learned patterns of NORMAL data in 7D feature space")
        
        # [7] Tính percentiles từ training scores
        logger.info("[7] Calculating score percentiles from training data...")
        scores = self.isolation_forest.decision_function(X_scaled)
        logger.info(f"    ✅ Calculated {len(scores)} scores from training data")
        
        percentiles = {p: float(np.percentile(scores, p)) for p in [50, 90, 95, 97.5, 99, 99.5]}
        self.score_percentiles = percentiles
        logger.info(f"    ✅ Score percentiles: {percentiles}")
        
        # Recommended anomaly threshold (50th percentile = median)
        self.bruteforce_score_threshold = float(np.percentile(scores, 50))
        logger.info(f"    ✅ Recommended anomaly threshold (50th percentile): {self.bruteforce_score_threshold:.6f}")
        logger.info("    - Lower score = more anomalous (brute-force)")
        logger.info("    - Higher score = more normal")
        
        self.is_trained = True
        
        # [8] Save model + metadata (prepared, actual save done externally)
        logger.info("[8] Model and metadata prepared for saving...")
        logger.info("    ✅ Model components ready:")
        logger.info("       - isolation_forest: 300 trees trained")
        logger.info("       - scaler: StandardScaler fitted")
        logger.info("       - feature_names: 7 features selected")
        logger.info("       - score_percentiles: calculated")
        logger.info("       - bruteforce_score_threshold: calculated")
        logger.info("    📝 Note: Use detector.save_model(path) to save .pkl file")
        logger.info("    📝 Note: Save metadata JSON separately if needed")
        
        logger.info("=" * 70)
        logger.info("✅ Optimized model trained successfully!")
        logger.info(f"   - Training samples: {len(clean_logs)}")
        logger.info(f"   - Features used: {len(self.feature_names)}")
        logger.info(f"   - All 8 workflow steps completed!")
        logger.info("=" * 70)
        
        return X_scaled, self.feature_names
    
    def train_from_path(self, jsonl_path: str, is_normal_log_format: bool = False) -> None:
        """
        Huấn luyện từ file JSONL sạch (đọc streaming).
        
        Args:
            jsonl_path: Path to JSONL file
            is_normal_log_format: If True, convert from normal.log format to detector format
        """
        clean_logs = []
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    log_entry = json.loads(line)
                    # Convert format if needed
                    if is_normal_log_format:
                        log_entry = convert_normal_log_to_detector_format(log_entry)
                    clean_logs.append(log_entry)
                except json.JSONDecodeError as e:
                    logger.warning(f"Skipping invalid JSON at line {line_num}: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Error processing line {line_num}: {e}")
                    continue
        
        logger.info(f"Loaded {len(clean_logs)} log entries from {jsonl_path}")
        self.train(clean_logs)
    
    def predict_single(self, log_entry, threshold=None, rule_flags=None):
        """
        Predict single log entry với hybrid detection (Rule-based + AI-based)
        
        Args:
            rule_flags: Dict với keys 'rule_1', 'rule_2', 'rule_3', 'rule_4'
                       True = enable rule, False = disable rule
                       None = enable all rules (default)
        
        Logic detection:
        - Bước 1 (Priority 1): Rule-based detection
          * Rule 1: >5 username khác nhau trong 1 phút → username_enumeration
          * Rule 2: >5 password cho 1 user trong 1 phút → password_spraying
          * Rule 3: >15 requests/phút từ 1 IP → high_request_rate
          * Nếu có pattern → kết luận ANOMALY ngay
        
        - Bước 3: AI-based detection (Isolation Forest)
          * Tính RawAnomalyScore từ 7 features
          * Nếu score < threshold → AI phát hiện anomaly
          * Rule 4: Nếu AI phát hiện nhưng tổng log < 3 → không phải anomaly (tránh false positive)
        
        Returns:
            Tuple: (is_anomaly, normalized_score, patterns, confidence, threat_level, 
                   risk_score, raw_anomaly_score, decision_threshold, features)
        """
        if not self.is_trained:
            raise ValueError("Model chưa được train!")
        
        # Default: enable all rules if rule_flags not provided
        if rule_flags is None:
            rule_flags = {
                'rule_1': True,
                'rule_2': True,
                'rule_3': True,
                'rule_4': True
            }
        
        # Select decision threshold
        # Isolation Forest decision_function trả về score dương:
        # - Score càng THẤP (< threshold) = càng bất thường (anomaly)
        # - Score càng CAO (> threshold) = càng bình thường (normal)
        # Default threshold = 50th percentile từ training data
        if threshold is not None:
            decision_threshold = float(threshold)
        elif getattr(self, 'decision_threshold', None) is not None:
            decision_threshold = float(self.decision_threshold)
        elif hasattr(self, 'bruteforce_score_threshold') and self.bruteforce_score_threshold is not None:
            # Dùng threshold từ training (50th percentile)
            decision_threshold = float(self.bruteforce_score_threshold)
        else:
            # Fallback: dùng 50th percentile mặc định (0.095468 từ training)
            decision_threshold = 0.095468
        
        # Extract features (trả về cả metrics để dùng lại cho rule-based detection)
        features, metrics_1min, current_time = self.extract_bruteforce_features(log_entry)
        
        # Create DataFrame
        df = pd.DataFrame([features])
        
        # Encode categorical features
        categorical_features = ['method']
        for feature in categorical_features:
            if feature in df.columns:
                raw_val = str(df[feature].iloc[0])
                if feature == 'method':
                    norm_val = 'POST' if raw_val.upper() == 'POST' else 'GET'
                    df.loc[:, feature] = norm_val
                else:
                    norm_val = raw_val
                
                if feature in self.label_encoders:
                    le = self.label_encoders[feature]
                    classes = set(getattr(le, 'classes_', []))
                    if norm_val in classes:
                        df[f'{feature}_encoded'] = le.transform(df[feature].astype(str))
                    else:
                        if feature == 'method':
                            df[f'{feature}_encoded'] = 1 if norm_val == 'POST' else 0
                        else:
                            df[f'{feature}_encoded'] = 0
                else:
                    if feature == 'method':
                        df[f'{feature}_encoded'] = 1 if norm_val == 'POST' else 0
                    else:
                        df[f'{feature}_encoded'] = 0
        
        # Select features - CRITICAL: Only use features that model was trained with
        # Model should be trained with exactly 7 features (no requests_per_minute, requests_per_second, etc.)
        available_features = [f for f in self.feature_names if f in df.columns]
        missing_features = set(self.feature_names) - set(available_features)
        
        if missing_features:
            # This should NOT happen if model was trained correctly
            logger.error(f"❌ CRITICAL: Model expects features that are not in DataFrame: {missing_features}")
            logger.error(f"   Model feature_names: {self.feature_names}")
            logger.error(f"   Available in DataFrame: {list(df.columns)}")
            logger.error(f"   This indicates model was trained with different features than current code!")
            logger.error(f"   Solution: Retrain model with current feature set (7 features)")
            # Add missing features with default value 0 (but this will cause false positives!)
            for feature in missing_features:
                df[feature] = 0
            available_features = self.feature_names
        
        # Check for extra features in DataFrame that model doesn't expect
        # These are expected (extracted for logging/risk score but not used for prediction)
        # NO LOGGING - this is expected behavior and should be silent
        # Extra features like 'status', 'bruteforce_risk_score', etc. are extracted
        # but NOT used for prediction (only 7 features are used)
        extra_features = set(df.columns) - set(self.feature_names)
        # Silently ignore all extra features - no logging at all
        # Expected extra features: status, bruteforce_risk_score, bruteforce_risk_score_log,
        # has_failed_login, has_username_enumeration, has_password_spraying
        # These are extracted for logging/risk calculation but NOT used for AI prediction
        # No need to log - this is by design
        
        X = df[available_features].fillna(0)
        
        # Verify we're using exactly the 7 features for prediction
        if len(available_features) != 7:
            logger.error(f"❌ CRITICAL: Expected 7 features for prediction, got {len(available_features)}")
            logger.error(f"   Features used: {available_features}")
            logger.error(f"   Model expects: {self.feature_names}")
        else:
            # Log once to confirm we're using correct features
            if not hasattr(self, '_features_verified'):
                logger.info(f"✅ Verified: Using exactly 7 features for RawAnomalyScore calculation:")
                for i, fname in enumerate(available_features, 1):
                    logger.info(f"   {i}. {fname}")
                self._features_verified = True
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score from Isolation Forest using ONLY the 7 features
        # This is the RawAnomalyScore
        score = self.isolation_forest.decision_function(X_scaled)[0]
        anomaly_score = score
        
        # ===== BƯỚC 1: RULE-BASED DETECTION (Priority 1) =====
        remote_ip = log_entry.get('remote_ip', '')
        
        # Dùng metrics đã tính trong extract_bruteforce_features() (TRƯỚC khi track request hiện tại)
        # Điều này đảm bảo metrics phản ánh trạng thái trước request hiện tại
        
        has_bruteforce_pattern = False
        patterns = []
        
        # Rule 1: >5 different usernames in 1 minute → username_enumeration
        if rule_flags.get('rule_1', True) and metrics_1min.get('unique_usernames', 0) > 5:
            has_bruteforce_pattern = True
            patterns.append('username_enumeration')
        
        # Rule 2: >5 passwords for 1 user in 1 minute → password_spraying
        if rule_flags.get('rule_2', True):
            username, _ = extract_credentials_from_payload(
                log_entry.get('payload', ''),
                log_entry.get('query_string', '')
            )
            if username and self.bruteforce_tracker.get_password_spraying(remote_ip, username, time_window_seconds=60, current_time=current_time):
                has_bruteforce_pattern = True
                patterns.append('password_spraying')
        
        # Rule 3: >15 requests/minute from 1 IP → high_request_rate
        if rule_flags.get('rule_3', True) and metrics_1min.get('requests_per_minute', 0) > 15:
            has_bruteforce_pattern = True
            patterns.append('high_request_rate')
        
        # Risk score calculation (for threat level determination)
        risk_score = features.get('bruteforce_risk_score', 0)
        
        # Determine threat level based on risk score
        if risk_score >= 60:
            threat_level = 'CRITICAL'
        elif risk_score >= 40:
            threat_level = 'HIGH'
        elif risk_score >= 20:
            threat_level = 'MEDIUM'
        elif risk_score >= 10:
            threat_level = 'LOW'
        else:
            threat_level = 'NONE'
        
        # ===== BƯỚC 3: AI-BASED DETECTION =====
        # Isolation Forest: score càng THẤP = càng bất thường
        # Threshold: score < decision_threshold → anomaly
        ai_detected_anomaly = anomaly_score < decision_threshold
        
        # ===== FINAL DECISION LOGIC: Kết hợp Bước 1 và Bước 3 =====
        if has_bruteforce_pattern:
            # Bước 1: Rule-based phát hiện pattern rõ ràng → ANOMALY ngay
            is_anomaly = True
        elif ai_detected_anomaly:
            # Bước 3: AI phát hiện anomaly → Check Rule 4 để tránh false positive
            # Rule 4: Nếu AI phát hiện nhưng tổng log < 3 → không phải anomaly (tránh false positive)
            total_logs_in_window = metrics_1min.get('requests_count', 0)
            if rule_flags.get('rule_4', True) and total_logs_in_window < 3:
                # False positive filter: quá ít log để kết luận
                is_anomaly = False
                patterns.append('ai_false_positive_filtered')
            else:
                # AI phát hiện và có đủ log → ANOMALY
                is_anomaly = True
                patterns.append('ai_detected')
        else:
            # Không có pattern và AI không phát hiện → NORMAL
            is_anomaly = False
        
        # Determine confidence level
        if has_bruteforce_pattern:
            # Rule-based phát hiện pattern rõ ràng → High confidence
            confidence = "High"
        elif is_anomaly and ai_detected_anomaly:
            # AI-based detection: Score càng thấp (so với threshold) = confidence càng cao
            score_diff = decision_threshold - anomaly_score  # Càng dương = càng bất thường
            if score_diff > 0.05:  # Score thấp hơn threshold > 0.05
                confidence = "High"
            elif score_diff > 0.03:  # Score thấp hơn threshold > 0.03
                confidence = "Medium-High"
            elif score_diff > 0.01:  # Score thấp hơn threshold > 0.01
                confidence = "Medium"
            else:
                confidence = "Low"
        else:
            # Normal case
            confidence = "Low"
        
        # Return results with normalized score (0-1, higher = more anomalous)
        normalized_score = 1 / (1 + np.exp(anomaly_score))
        
        # Return extended tuple with raw anomaly score and decision threshold for debugging
        return is_anomaly, normalized_score, patterns, confidence, threat_level, risk_score, anomaly_score, decision_threshold, features
    
    def predict_batch(self, logs, threshold=0.49):
        """Dự đoán theo lô để tăng tốc khi kiểm nhiều bản ghi trên API."""
        results = []
        for log in logs:
            try:
                res = self.predict_single(log, threshold=threshold)
            except Exception as e:
                logger.warning(f"predict_batch error: {e}")
                # Return extended tuple format matching predict_single
                res = (False, 0.0, [], "Error", "NONE", 0.0, None, threshold, {})
            results.append(res)
        return results
    
    def save_model(self, model_path):
        """Save trained model with metadata"""
        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'contamination': self.contamination,
            'random_state': self.random_state,
            'metadata': {
                'score_percentiles': getattr(self, 'score_percentiles', None),
                'bruteforce_score_threshold': getattr(self, 'bruteforce_score_threshold', None),
                'decision_threshold': getattr(self, 'decision_threshold', None)
            }
        }
        dirn = os.path.dirname(model_path)
        if dirn:
            os.makedirs(dirn, exist_ok=True)
        joblib.dump(model_data, model_path)
        logger.info(f"✅ Optimized model saved to {model_path}")
    
    def load_model(self, model_path):
        """Load trained model"""
        model_data = joblib.load(model_path)
        
        self.isolation_forest = model_data['isolation_forest']
        self.scaler = model_data['scaler']
        self.label_encoders = model_data['label_encoders']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        self.contamination = model_data['contamination']
        self.random_state = model_data['random_state']
        
        # Load metadata if available
        if 'metadata' in model_data:
            metadata = model_data['metadata']
            self.score_percentiles = metadata.get('score_percentiles', None)
            self.bruteforce_score_threshold = metadata.get('bruteforce_score_threshold', None)
            self.decision_threshold = metadata.get('decision_threshold', None)
        
        # Expected feature set (7 features)
        expected_features = {
            'failed_login_rate',
            'unique_usernames_tried',
            'unique_passwords_tried',
            'time_between_attempts',
            'failed_logins_1min',
            'spamming_username',
            'spamming_password'
        }
        
        # Validate feature names
        model_features_set = set(self.feature_names)
        if model_features_set != expected_features:
            logger.error("=" * 70)
            logger.error("❌ CRITICAL: Model feature mismatch!")
            logger.error("=" * 70)
            logger.error(f"   Model was trained with {len(self.feature_names)} features:")
            for i, f in enumerate(self.feature_names, 1):
                logger.error(f"      {i}. {f}")
            logger.error(f"\n   Expected {len(expected_features)} features:")
            for i, f in enumerate(sorted(expected_features), 1):
                logger.error(f"      {i}. {f}")
            
            extra = model_features_set - expected_features
            missing = expected_features - model_features_set
            if extra:
                logger.error(f"\n   ❌ Extra features in model (should be removed): {extra}")
            if missing:
                logger.error(f"\n   ❌ Missing features in model: {missing}")
            
            logger.error("\n   ⚠️  This will cause FALSE POSITIVES!")
            logger.error("   Solution: Retrain model with current code (7 features)")
            logger.error("=" * 70)
        else:
            logger.info(f"✅ Model feature names validated: {len(self.feature_names)} features match expected set")
        
        # Try to augment from JSON metadata file if exists
        try:
            json_meta_path = os.path.join(os.path.dirname(model_path), 'optimized_bruteforce_metadata.json')
            if os.path.exists(json_meta_path):
                with open(json_meta_path, 'r', encoding='utf-8') as f:
                    jmeta = json.load(f)
                    if jmeta.get('decision_threshold') is not None:
                        self.decision_threshold = float(jmeta['decision_threshold'])
                    # Check for feature names mismatch (for debugging)
                    if jmeta.get('feature_names') is not None:
                        json_feature_names = jmeta['feature_names']
                        if set(json_feature_names) != set(self.feature_names):
                            logger.warning(f"⚠️  Feature names mismatch between model file and JSON metadata")
                            logger.warning(f"   Model file: {self.feature_names}")
                            logger.warning(f"   JSON metadata: {json_feature_names}")
                            logger.warning(f"   Using model file feature names (scaler/isolation forest expect these)")
        except Exception as e:
            logger.debug(f"Could not load JSON metadata: {e}")
            pass
        
        logger.info(f"✅ Optimized model loaded from {model_path}")
        return model_data


def train_optimized_model(data_path: str = 'normal.log', is_normal_log_format: bool = True, 
                          max_samples: Optional[int] = None):
    """
    Train optimized model
    
    Args:
        data_path: Path to training data file (default: 'normal.log')
        is_normal_log_format: If True, convert from normal.log format to detector format
        max_samples: Maximum number of samples to use for training (None = use all)
    """
    logger.info("TRAINING OPTIMIZED BRUTE-FORCE DETECTOR")
    logger.info("=" * 50)
    
    # Load clean data
    clean_logs = []
    
    if not os.path.exists(data_path):
        logger.error(f"Data file not found: {data_path}")
        logger.error("Please provide a valid data file for training.")
        return None
    
    logger.info(f"Loading data from: {data_path}")
    logger.info(f"Format: {'normal.log format' if is_normal_log_format else 'detector format'}")
    
    with open(data_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            # Limit samples if specified
            if max_samples and len(clean_logs) >= max_samples:
                logger.info(f"Reached max_samples limit ({max_samples}), stopping data loading")
                break
            
            try:
                log_entry = json.loads(line.strip())
                # Convert format if needed
                if is_normal_log_format:
                    log_entry = convert_normal_log_to_detector_format(log_entry)
                clean_logs.append(log_entry)
            except json.JSONDecodeError as e:
                if line_num <= 10:  # Only log first 10 errors to avoid spam
                    logger.warning(f"Skipping invalid JSON at line {line_num}: {e}")
                continue
            except Exception as e:
                if line_num <= 10:
                    logger.warning(f"Error processing line {line_num}: {e}")
                continue
    
    if not clean_logs:
        logger.error(f"No valid log entries found in {data_path}")
        logger.error("Please check the file format and try again.")
        return None
    
    logger.info(f"✅ Loaded {len(clean_logs)} log entries from {data_path}")
    if max_samples and len(clean_logs) == max_samples:
        logger.info(f"   (Limited to {max_samples} samples)")
    
    # Create optimized detector
    logger.info("Initializing detector...")
    detector = OptimizedBruteForceDetector(
        contamination='auto',
        random_state=42,
        n_estimators=300,
        max_features=1.0,
        n_jobs=-1
    )
    
    # Train
    logger.info("Starting training...")
    X_scaled, feature_names = detector.train(clean_logs)
    
    # Save model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/optimized_bruteforce_detector.pkl'
    detector.save_model(model_path)
    logger.info(f"✅ Model saved to {model_path}")
    
    # Save metadata to JSON
    metadata = {
        "score_percentiles": getattr(detector, "score_percentiles", None),
        "bruteforce_score_threshold": getattr(detector, "bruteforce_score_threshold", None),
        "feature_names": detector.feature_names,
        "contamination": detector.contamination,
        "random_state": detector.random_state,
        "decision_threshold": getattr(detector, "decision_threshold", None),
        "training_samples": len(clean_logs),
        "data_source": data_path
    }
    metadata_path = "models/optimized_bruteforce_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"🧾 Saved model metadata to {metadata_path}")
    
    logger.info("🎉 Optimized model training completed!")
    logger.info(f"   - Training samples: {len(clean_logs)}")
    logger.info(f"   - Features: {len(feature_names)}")
    logger.info(f"   - Model path: {model_path}")
    
    return detector


if __name__ == "__main__":
    # Train with normal.log file
    # Try to find normal.log in current directory or parent directory
    import os
    data_path = 'normal.log'
    if not os.path.exists(data_path):
        # Try parent directory
        parent_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'normal.log')
        if os.path.exists(parent_path):
            data_path = parent_path
            logger.info(f"Found normal.log in parent directory: {data_path}")
        else:
            logger.error(f"normal.log not found in current directory or parent directory")
            logger.error(f"Current directory: {os.getcwd()}")
            logger.error(f"Script directory: {os.path.dirname(os.path.abspath(__file__))}")
            logger.error(f"Please ensure normal.log exists in one of these locations")
            sys.exit(1)
    
    # You can limit samples for faster training: max_samples=10000
    train_optimized_model(
        data_path=data_path,
        is_normal_log_format=True,
        max_samples=None  # Use all samples, or set a number like 50000 for faster training
    )


