#!/usr/bin/env python3
"""Script để kiểm tra features trong model file"""
import joblib
import json
import os

model_path = 'models/optimized_bruteforce_detector.pkl'
metadata_path = 'models/optimized_bruteforce_metadata.json'

print("=" * 70)
print("KIỂM TRA MODEL FEATURES")
print("=" * 70)

# Check model file
if os.path.exists(model_path):
    print(f"\n📦 Loading model from: {model_path}")
    model_data = joblib.load(model_path)
    model_features = model_data.get('feature_names', [])
    print(f"   Model file feature_names ({len(model_features)} features):")
    for i, f in enumerate(model_features, 1):
        print(f"      {i}. {f}")
else:
    print(f"\n❌ Model file not found: {model_path}")
    model_features = []

# Check metadata JSON
if os.path.exists(metadata_path):
    print(f"\n📄 Loading metadata from: {metadata_path}")
    with open(metadata_path, 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    json_features = metadata.get('feature_names', [])
    print(f"   JSON metadata feature_names ({len(json_features)} features):")
    for i, f in enumerate(json_features, 1):
        print(f"      {i}. {f}")
else:
    print(f"\n❌ Metadata file not found: {metadata_path}")
    json_features = []

# Compare
print("\n" + "=" * 70)
print("SO SÁNH")
print("=" * 70)

if model_features and json_features:
    if set(model_features) == set(json_features):
        print("✅ Model file và JSON metadata KHỚP NHAU")
    else:
        print("❌ Model file và JSON metadata KHÔNG KHỚP!")
        only_in_model = set(model_features) - set(json_features)
        only_in_json = set(json_features) - set(model_features)
        if only_in_model:
            print(f"   Chỉ có trong model file: {only_in_model}")
        if only_in_json:
            print(f"   Chỉ có trong JSON: {only_in_json}")

# Expected features (7 features)
expected_features = [
    'failed_login_rate',
    'unique_usernames_tried',
    'unique_passwords_tried',
    'time_between_attempts',
    'failed_logins_1min',
    'spamming_username',
    'spamming_password'
]

print(f"\n📋 Expected features (7 features):")
for i, f in enumerate(expected_features, 1):
    print(f"      {i}. {f}")

if model_features:
    if set(model_features) == set(expected_features):
        print("\n✅ Model file KHỚP với expected features (7 features)")
    else:
        print("\n❌ Model file KHÔNG KHỚP với expected features!")
        extra = set(model_features) - set(expected_features)
        missing = set(expected_features) - set(model_features)
        if extra:
            print(f"   Features thừa trong model: {extra}")
        if missing:
            print(f"   Features thiếu trong model: {missing}")

print("\n" + "=" * 70)

