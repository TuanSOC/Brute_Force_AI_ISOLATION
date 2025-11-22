#!/usr/bin/env python3
"""
Brute-Force Tracker - Thread-safe IP tracking system
- Track requests, failed logins, usernames, passwords per IP
- Time-window based tracking (1 minute, 5 minutes, 1 hour)
- Auto cleanup old data
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class BruteForceTracker:
    """Thread-safe tracker for brute-force attack patterns"""
    
    def __init__(self, cleanup_interval_seconds: int = 300):
        """
        Initialize tracker
        
        Args:
            cleanup_interval_seconds: Interval to run cleanup (default: 5 minutes)
        """
        self._lock = threading.RLock()
        self._cleanup_interval = cleanup_interval_seconds
        self._last_cleanup = time.time()
        
        # Per-IP tracking data structures
        # Format: {ip: deque([(timestamp, status, username, password), ...])}
        self._ip_requests = defaultdict(lambda: deque())
        
        # Per-username tracking: {username: deque([(timestamp, ip), ...])}
        self._username_requests = defaultdict(lambda: deque())
        
        # Per-password tracking: {password: deque([(timestamp, ip), ...])}
        self._password_requests = defaultdict(lambda: deque())
        
        # Quick access counters (for performance)
        # Format: {ip: {'requests': count, 'failed_logins': count, 'usernames': set(), 'passwords': set()}}
        self._ip_stats = defaultdict(lambda: {
            'requests': 0,
            'failed_logins': 0,
            'usernames': set(),
            'passwords': set(),
            'last_request_time': 0
        })
    
    def track_request(self, ip: str, status: int, username: Optional[str] = None, 
                     password: Optional[str] = None, timestamp: Optional[float] = None):
        """
        Track a request from an IP
        
        Args:
            ip: Remote IP address
            status: HTTP status code
            username: Username if available (from query/payload)
            password: Password if available (from query/payload)
            timestamp: Request timestamp (default: current time)
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Determine if this is a failed login attempt (only status 320 = fail)
        is_failed_login = (status == 320)
        
        with self._lock:
            # Add to request history
            self._ip_requests[ip].append((timestamp, status, username, password))
            
            # Track username and password separately for spamming detection
            if username:
                self._username_requests[username].append((timestamp, ip))
                stats = self._ip_stats[ip]
                stats['usernames'].add(username)
            
            if password:
                self._password_requests[password].append((timestamp, ip))
                stats = self._ip_stats[ip]
                stats['passwords'].add(password)
            
            # Update stats
            stats = self._ip_stats[ip]
            stats['requests'] += 1
            stats['last_request_time'] = timestamp
            
            if is_failed_login:
                stats['failed_logins'] += 1
            
            # Auto cleanup if needed
            if timestamp - self._last_cleanup > self._cleanup_interval:
                self._cleanup_old_data(timestamp)
                self._last_cleanup = timestamp
    
    def get_metrics(self, ip: str, time_window_seconds: int = 60, 
                   current_time: Optional[float] = None) -> Dict:
        """
        Get metrics for an IP within a time window
        
        Args:
            ip: Remote IP address
            time_window_seconds: Time window in seconds (default: 60 = 1 minute)
            current_time: Current timestamp (default: current time)
        
        Returns:
            Dictionary with metrics:
            - requests_count: Total requests in window
            - failed_login_count: Failed logins in window
            - unique_usernames: Number of unique usernames tried
            - unique_passwords: Number of unique passwords tried
            - requests_per_second: Requests per second
            - requests_per_minute: Requests per minute
            - failed_login_rate: Failed logins / total requests
            - has_rapid_attempts: True if >3 requests in 10 seconds
        """
        if current_time is None:
            current_time = time.time()
        
        cutoff_time = current_time - time_window_seconds
        
        with self._lock:
            if ip not in self._ip_requests:
                return self._empty_metrics()
            
            # Filter requests within time window
            requests = self._ip_requests[ip]
            window_requests = [
                (ts, status, username, password)
                for ts, status, username, password in requests
                if ts >= cutoff_time
            ]
            
            if not window_requests:
                return self._empty_metrics()
            
            # Calculate metrics
            requests_count = len(window_requests)
            failed_logins = sum(1 for _, status, _, _ in window_requests 
                              if status == 320)  # Only status 320 = fail
            
            usernames = set(username for _, _, username, _ in window_requests if username)
            passwords = set(password for _, _, _, password in window_requests if password)
            
            # Calculate rates
            # Use actual time window (not time_span between first and last request)
            # This ensures requests_per_minute is calculated correctly per IP
            requests_per_second = requests_count / time_window_seconds if time_window_seconds > 0 else 0.0
            requests_per_minute = requests_per_second * 60
            failed_login_rate = failed_logins / requests_count if requests_count > 0 else 0.0
            
            # Check for rapid attempts (last 10 seconds)
            recent_cutoff = current_time - 10
            recent_requests = [ts for ts, _, _, _ in window_requests if ts >= recent_cutoff]
            has_rapid_attempts = len(recent_requests) > 3
            
            return {
                'requests_count': requests_count,
                'failed_login_count': failed_logins,
                'unique_usernames': len(usernames),
                'unique_passwords': len(passwords),
                'usernames': list(usernames),  # For debugging
                'passwords': list(passwords),  # For debugging (be careful with this!)
                'requests_per_second': requests_per_second,
                'requests_per_minute': requests_per_minute,
                'failed_login_rate': failed_login_rate,
                'has_rapid_attempts': has_rapid_attempts,
                'time_window_seconds': time_window_seconds
            }
    
    def get_username_enumeration(self, ip: str, time_window_seconds: int = 60,
                                current_time: Optional[float] = None) -> bool:
        """
        Check if IP is trying username enumeration (>5 different usernames in time window)
        
        Args:
            ip: Remote IP address
            time_window_seconds: Time window (default: 60 = 1 minute)
            current_time: Current timestamp
        
        Returns:
            True if username enumeration detected
        """
        metrics = self.get_metrics(ip, time_window_seconds, current_time)
        return metrics['unique_usernames'] > 5
    
    def get_password_spraying(self, ip: str, username: str, time_window_seconds: int = 60,
                             current_time: Optional[float] = None) -> bool:
        """
        Check if IP is trying password spraying for a specific username
        (>5 different passwords for 1 user in time window)
        
        Args:
            ip: Remote IP address
            username: Username to check
            time_window_seconds: Time window (default: 60 = 1 minute)
            current_time: Current timestamp
        
        Returns:
            True if password spraying detected
        """
        if current_time is None:
            current_time = time.time()
        
        cutoff_time = current_time - time_window_seconds
        
        with self._lock:
            if ip not in self._ip_requests:
                return False
            
            # Count unique passwords for this username in time window
            passwords = set()
            for ts, status, uname, pwd in self._ip_requests[ip]:
                if ts >= cutoff_time and uname == username and pwd:
                    passwords.add(pwd)
            
            return len(passwords) > 5
    
    def get_username_spamming_count(self, username: str, time_window_seconds: int = 3600,
                                    current_time: Optional[float] = None) -> int:
        """
        Get number of times a username was used in time window
        
        Args:
            username: Username to check
            time_window_seconds: Time window (default: 3600 = 1 hour)
            current_time: Current timestamp
        
        Returns:
            Number of times username was used
        """
        if current_time is None:
            current_time = time.time()
        
        cutoff_time = current_time - time_window_seconds
        
        with self._lock:
            if username not in self._username_requests:
                return 0
            
            requests = self._username_requests[username]
            count = sum(1 for ts, _ in requests if ts >= cutoff_time)
            return count
    
    def get_password_spamming_count(self, password: str, time_window_seconds: int = 3600,
                                    current_time: Optional[float] = None) -> int:
        """
        Get number of times a password was used in time window
        
        Args:
            password: Password to check
            time_window_seconds: Time window (default: 3600 = 1 hour)
            current_time: Current timestamp
        
        Returns:
            Number of times password was used
        """
        if current_time is None:
            current_time = time.time()
        
        cutoff_time = current_time - time_window_seconds
        
        with self._lock:
            if password not in self._password_requests:
                return 0
            
            requests = self._password_requests[password]
            count = sum(1 for ts, _ in requests if ts >= cutoff_time)
            return count
    
    def _cleanup_old_data(self, current_time: float, max_age_seconds: int = 3600):
        """
        Remove old data (older than max_age_seconds)
        
        Args:
            current_time: Current timestamp
            max_age_seconds: Maximum age in seconds (default: 3600 = 1 hour)
        """
        cutoff_time = current_time - max_age_seconds
        
        with self._lock:
            # Clean up request history
            ips_to_remove = []
            for ip, requests in self._ip_requests.items():
                # Remove old requests
                while requests and requests[0][0] < cutoff_time:
                    requests.popleft()
                
                # Remove IP if no recent requests
                if not requests:
                    ips_to_remove.append(ip)
            
            # Remove empty IPs
            for ip in ips_to_remove:
                del self._ip_requests[ip]
                if ip in self._ip_stats:
                    del self._ip_stats[ip]
            
            # Clean up username requests
            usernames_to_remove = []
            for username, requests in self._username_requests.items():
                while requests and requests[0][0] < cutoff_time:
                    requests.popleft()
                if not requests:
                    usernames_to_remove.append(username)
            
            for username in usernames_to_remove:
                del self._username_requests[username]
            
            # Clean up password requests
            passwords_to_remove = []
            for password, requests in self._password_requests.items():
                while requests and requests[0][0] < cutoff_time:
                    requests.popleft()
                if not requests:
                    passwords_to_remove.append(password)
            
            for password in passwords_to_remove:
                del self._password_requests[password]
    
    def _empty_metrics(self) -> Dict:
        """Return empty metrics dictionary"""
        return {
            'requests_count': 0,
            'failed_login_count': 0,
            'unique_usernames': 0,
            'unique_passwords': 0,
            'usernames': [],
            'passwords': [],
            'requests_per_second': 0.0,
            'requests_per_minute': 0.0,
            'failed_login_rate': 0.0,
            'has_rapid_attempts': False,
            'time_window_seconds': 0
        }
    
    def get_all_ips(self) -> List[str]:
        """Get list of all tracked IPs"""
        with self._lock:
            return list(self._ip_requests.keys())
    
    def clear_ip(self, ip: str):
        """Clear tracking data for a specific IP"""
        with self._lock:
            if ip in self._ip_requests:
                del self._ip_requests[ip]
            if ip in self._ip_stats:
                del self._ip_stats[ip]
    
    def clear_all(self):
        """Clear all tracking data"""
        with self._lock:
            self._ip_requests.clear()
            self._ip_stats.clear()


