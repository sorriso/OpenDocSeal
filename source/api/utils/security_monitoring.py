"""
Path: infrastructure/source/api/utils/security_monitoring.py
Version: 1
"""

import asyncio
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field
import json

from ..database import log_audit_event
from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: str
    severity: str  # low, medium, high, critical
    source_ip: str
    user_id: Optional[str]
    endpoint: str
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = None


@dataclass  
class ThreatIndicator:
    """Threat indicator with scoring"""
    indicator_type: str
    value: str
    score: float  # 0.0 to 1.0
    first_seen: datetime
    last_seen: datetime
    count: int = 1


class SecurityMonitor:
    """
    Real-time security monitoring and threat detection system
    
    Monitors for suspicious activities, brute force attacks, and anomalies.
    """
    
    def __init__(self):
        self.enabled = settings.security_monitoring_enabled
        
        # Event tracking
        self.events: deque = deque(maxlen=10000)  # Keep last 10k events
        self.failed_auths: defaultdict = defaultdict(list)  # IP -> timestamps
        self.request_patterns: defaultdict = defaultdict(list)  # IP -> request info
        self.user_activities: defaultdict = defaultdict(list)  # user_id -> activities
        
        # Threat indicators
        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        
        # Configuration
        self.failed_auth_threshold = settings.failed_auth_threshold
        self.failed_auth_window = settings.failed_auth_window
        self.suspicious_activity_alert = settings.suspicious_activity_alert
        
        # Pattern detection
        self.sql_injection_patterns = [
            r'union\s+select',
            r'or\s+1\s*=\s*1',
            r'drop\s+table',
            r'delete\s+from',
            r'insert\s+into',
            r'update\s+.*\s+set'
        ]
        
        self.xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*='
        ]
        
        # Anomaly detection
        self.baseline_patterns: Dict[str, Any] = {}
        
        logger.info(f"Security monitoring initialized (enabled: {self.enabled})")
    
    async def log_security_event(
        self,
        event_type: str,
        severity: str,
        source_ip: str,
        endpoint: str,
        details: Dict[str, Any],
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> SecurityEvent:
        """
        Log security event and perform real-time analysis
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            source_ip: Source IP address
            endpoint: Endpoint being accessed
            details: Event details
            user_id: Optional user ID
            correlation_id: Optional correlation ID
            
        Returns:
            SecurityEvent object
        """
        if not self.enabled:
            return None
        
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            user_id=user_id,
            endpoint=endpoint,
            details=details,
            correlation_id=correlation_id
        )
        
        # Store event
        self.events.append(event)
        
        # Real-time analysis
        await self._analyze_event(event)
        
        # Log to audit system
        await log_audit_event(
            action=f"security_event_{event_type}",
            user_id=user_id,
            details={
                "event_type": event_type,
                "severity": severity,
                "endpoint": endpoint,
                "source_ip": source_ip,
                **details
            },
            ip_address=source_ip,
            correlation_id=correlation_id
        )
        
        logger.info(f"Security event logged: {event_type} ({severity}) from {source_ip}")
        
        return event
    
    async def _analyze_event(self, event: SecurityEvent):
        """Perform real-time analysis of security event"""
        
        # Failed authentication analysis
        if event.event_type == "failed_authentication":
            await self._analyze_failed_auth(event)
        
        # Suspicious request patterns
        if event.event_type == "suspicious_request":
            await self._analyze_request_patterns(event)
        
        # User behavior anomalies
        if event.user_id:
            await self._analyze_user_behavior(event)
        
        # Threat indicator updates
        await self._update_threat_indicators(event)
    
    async def _analyze_failed_auth(self, event: SecurityEvent):
        """Analyze failed authentication patterns"""
        ip = event.source_ip
        current_time = event.timestamp
        
        # Add to failed auth tracking
        self.failed_auths[ip].append(current_time)
        
        # Clean old entries
        cutoff_time = current_time - timedelta(seconds=self.failed_auth_window)
        self.failed_auths[ip] = [
            ts for ts in self.failed_auths[ip] 
            if ts > cutoff_time
        ]
        
        # Check threshold
        failed_count = len(self.failed_auths[ip])
        if failed_count >= self.failed_auth_threshold:
            await self._trigger_alert(
                "brute_force_attack",
                "high",
                {
                    "source_ip": ip,
                    "failed_attempts": failed_count,
                    "time_window": self.failed_auth_window,
                    "first_attempt": min(self.failed_auths[ip]).isoformat(),
                    "last_attempt": max(self.failed_auths[ip]).isoformat()
                }
            )
    
    async def _analyze_request_patterns(self, event: SecurityEvent):
        """Analyze suspicious request patterns"""
        ip = event.source_ip
        
        # Track request patterns
        pattern_info = {
            "timestamp": event.timestamp,
            "endpoint": event.endpoint,
            "method": event.details.get("method", "unknown"),
            "user_agent": event.details.get("user_agent", ""),
            "payload_size": event.details.get("payload_size", 0)
        }
        
        self.request_patterns[ip].append(pattern_info)
        
        # Keep only recent requests (last hour)
        cutoff_time = event.timestamp - timedelta(hours=1)
        self.request_patterns[ip] = [
            req for req in self.request_patterns[ip]
            if req["timestamp"] > cutoff_time
        ]
        
        requests = self.request_patterns[ip]
        
        # Detect rapid requests (potential automated attack)
        if len(requests) >= 50:  # 50+ requests in the last hour
            recent_requests = [
                req for req in requests
                if req["timestamp"] > event.timestamp - timedelta(minutes=5)
            ]
            
            if len(recent_requests) >= 20:  # 20+ requests in 5 minutes
                await self._trigger_alert(
                    "rapid_requests",
                    "medium",
                    {
                        "source_ip": ip,
                        "requests_5min": len(recent_requests),
                        "requests_1hour": len(requests),
                        "endpoints": list(set(req["endpoint"] for req in recent_requests))
                    }
                )
        
        # Detect endpoint scanning
        unique_endpoints = set(req["endpoint"] for req in requests)
        if len(unique_endpoints) >= 10:  # Accessing 10+ different endpoints
            await self._trigger_alert(
                "endpoint_scanning",
                "medium",
                {
                    "source_ip": ip,
                    "unique_endpoints": len(unique_endpoints),
                    "total_requests": len(requests),
                    "endpoints": list(unique_endpoints)[:20]  # Limit for readability
                }
            )
    
    async def _analyze_user_behavior(self, event: SecurityEvent):
        """Analyze user behavior for anomalies"""
        user_id = event.user_id
        if not user_id:
            return
        
        # Track user activities
        activity_info = {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "endpoint": event.endpoint,
            "source_ip": event.source_ip,
            "severity": event.severity
        }
        
        self.user_activities[user_id].append(activity_info)
        
        # Keep activities from last 24 hours
        cutoff_time = event.timestamp - timedelta(hours=24)
        self.user_activities[user_id] = [
            act for act in self.user_activities[user_id]
            if act["timestamp"] > cutoff_time
        ]
        
        activities = self.user_activities[user_id]
        
        # Detect unusual IP usage (user accessing from multiple IPs)
        unique_ips = set(act["source_ip"] for act in activities)
        if len(unique_ips) >= 5:  # 5+ different IPs in 24 hours
            await self._trigger_alert(
                "user_multiple_ips",
                "medium",
                {
                    "user_id": user_id,
                    "unique_ips": len(unique_ips),
                    "ips": list(unique_ips),
                    "time_span_hours": 24
                }
            )
        
        # Detect high-severity events concentration
        high_severity_events = [
            act for act in activities
            if act["severity"] in ["high", "critical"]
        ]
        
        if len(high_severity_events) >= 3:  # 3+ high severity events
            await self._trigger_alert(
                "user_high_risk_behavior",
                "high",
                {
                    "user_id": user_id,
                    "high_severity_events": len(high_severity_events),
                    "event_types": [act["event_type"] for act in high_severity_events]
                }
            )
    
    async def _update_threat_indicators(self, event: SecurityEvent):
        """Update threat indicators based on event"""
        
        # IP-based indicators
        ip_key = f"ip:{event.source_ip}"
        if ip_key in self.threat_indicators:
            indicator = self.threat_indicators[ip_key]
            indicator.count += 1
            indicator.last_seen = event.timestamp
            
            # Increase score based on event severity
            severity_scores = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 0.9}
            score_increase = severity_scores.get(event.severity, 0.1)
            indicator.score = min(1.0, indicator.score + score_increase * 0.1)
            
        else:
            # Create new indicator
            severity_scores = {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 0.9}
            initial_score = severity_scores.get(event.severity, 0.2)
            
            self.threat_indicators[ip_key] = ThreatIndicator(
                indicator_type="ip",
                value=event.source_ip,
                score=initial_score,
                first_seen=event.timestamp,
                last_seen=event.timestamp
            )
        
        # User-based indicators (if applicable)
        if event.user_id:
            user_key = f"user:{event.user_id}"
            if event.severity in ["high", "critical"]:
                if user_key in self.threat_indicators:
                    indicator = self.threat_indicators[user_key]
                    indicator.count += 1
                    indicator.last_seen = event.timestamp
                    indicator.score = min(1.0, indicator.score + 0.2)
                else:
                    self.threat_indicators[user_key] = ThreatIndicator(
                        indicator_type="user",
                        value=event.user_id,
                        score=0.5,
                        first_seen=event.timestamp,
                        last_seen=event.timestamp
                    )
    
    async def _trigger_alert(
        self,
        alert_type: str,
        severity: str,
        details: Dict[str, Any]
    ):
        """Trigger security alert"""
        
        if not self.suspicious_activity_alert:
            return
        
        alert_data = {
            "alert_type": alert_type,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details
        }
        
        # Log alert
        logger.warning(f"SECURITY ALERT: {alert_type} ({severity}) - {json.dumps(details)}")
        
        # Store alert (could be sent to external monitoring system)
        await log_audit_event(
            action="security_alert",
            details=alert_data
        )
        
        # TODO: Integration with external alerting systems (Slack, email, etc.)
    
    async def check_injection_patterns(self, input_text: str) -> List[Dict[str, Any]]:
        """Check input for injection patterns"""
        threats = []
        
        if not input_text:
            return threats
        
        import re
        
        # Check SQL injection patterns
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                threats.append({
                    "type": "sql_injection",
                    "pattern": pattern,
                    "severity": "high"
                })
        
        # Check XSS patterns
        for pattern in self.xss_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                threats.append({
                    "type": "xss",
                    "pattern": pattern,
                    "severity": "medium"
                })
        
        return threats
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get current threat landscape summary"""
        current_time = datetime.now(timezone.utc)
        
        # Recent events (last hour)
        recent_events = [
            event for event in self.events
            if event.timestamp > current_time - timedelta(hours=1)
        ]
        
        # High-risk IPs
        high_risk_ips = [
            indicator for indicator in self.threat_indicators.values()
            if indicator.indicator_type == "ip" and indicator.score > 0.7
        ]
        
        # Active threats
        active_threats = len([
            indicator for indicator in self.threat_indicators.values()
            if indicator.last_seen > current_time - timedelta(hours=1)
        ])
        
        # Event type distribution
        event_types = {}
        for event in recent_events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        
        return {
            "monitoring_enabled": self.enabled,
            "recent_events": len(recent_events),
            "active_threats": active_threats,
            "high_risk_ips": len(high_risk_ips),
            "total_indicators": len(self.threat_indicators),
            "event_types": event_types,
            "top_threat_ips": [
                {"ip": ind.value, "score": ind.score, "count": ind.count}
                for ind in sorted(high_risk_ips, key=lambda x: x.score, reverse=True)[:5]
            ],
            "timestamp": current_time.isoformat()
        }
    
    async def cleanup_old_data(self):
        """Cleanup old monitoring data"""
        current_time = datetime.now(timezone.utc)
        cutoff_time = current_time - timedelta(hours=24)
        
        # Clean old failed auth data
        for ip in list(self.failed_auths.keys()):
            self.failed_auths[ip] = [
                ts for ts in self.failed_auths[ip]
                if ts > cutoff_time
            ]
            if not self.failed_auths[ip]:
                del self.failed_auths[ip]
        
        # Clean old threat indicators
        for key in list(self.threat_indicators.keys()):
            indicator = self.threat_indicators[key]
            if indicator.last_seen < cutoff_time - timedelta(hours=24):
                del self.threat_indicators[key]
        
        logger.debug("Security monitoring data cleanup completed")


# Global security monitor instance
_security_monitor: Optional[SecurityMonitor] = None


def get_security_monitor() -> SecurityMonitor:
    """Get global security monitor instance"""
    global _security_monitor
    
    if _security_monitor is None:
        _security_monitor = SecurityMonitor()
    
    return _security_monitor


async def log_security_event(
    event_type: str,
    severity: str,
    source_ip: str,
    endpoint: str,
    details: Dict[str, Any],
    user_id: Optional[str] = None,
    correlation_id: Optional[str] = None
) -> Optional[SecurityEvent]:
    """
    Convenience function to log security event
    
    Returns:
        SecurityEvent if monitoring is enabled
    """
    monitor = get_security_monitor()
    return await monitor.log_security_event(
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        endpoint=endpoint,
        details=details,
        user_id=user_id,
        correlation_id=correlation_id
    )