"""
Audit & Logging Module for SecureCorp Zero-Trust System
Handles authentication attempts, authorization decisions, policy evaluations,
and suspicious activity detection.
"""

import logging
import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
import os


class AuditEventType(Enum):
    """Enumeration of audit event types"""
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    TGT_ISSUED = "TGT_ISSUED"
    SERVICE_TICKET_ISSUED = "SERVICE_TICKET_ISSUED"
    TICKET_VALIDATION_SUCCESS = "TICKET_VALIDATION_SUCCESS"
    TICKET_VALIDATION_FAILURE = "TICKET_VALIDATION_FAILURE"
    ACCESS_REQUEST = "ACCESS_REQUEST"
    ACCESS_ALLOWED = "ACCESS_ALLOWED"
    ACCESS_DENIED = "ACCESS_DENIED"
    POLICY_EVALUATION = "POLICY_EVALUATION"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    REPLAY_ATTACK_DETECTED = "REPLAY_ATTACK_DETECTED"
    TICKET_TAMPERING_DETECTED = "TICKET_TAMPERING_DETECTED"
    PRIVILEGE_ESCALATION_ATTEMPT = "PRIVILEGE_ESCALATION_ATTEMPT"
    UNAUTHORIZED_ACCESS_ATTEMPT = "UNAUTHORIZED_ACCESS_ATTEMPT"


class SeverityLevel(Enum):
    """Severity levels for audit events"""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"


@dataclass
class AuditEvent:
    """Data class for audit events"""
    timestamp: str
    event_type: str
    severity: str
    user: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class AuditLogger:
    """Main audit logging system for SecureCorp"""

    def __init__(self, log_file: str = "audit.log", 
                 json_log_file: str = "audit_events.json",
                 suspicious_threshold: int = 5):
        """
        Initialize the audit logger.
        
        Args:
            log_file: Path to text log file
            json_log_file: Path to JSON structured log file
            suspicious_threshold: Failed attempts threshold to trigger alert
        """
        self.log_file = log_file
        self.json_log_file = json_log_file
        self.suspicious_threshold = suspicious_threshold
        self.failed_login_attempts: Dict[str, int] = {}
        self.events_log: List[AuditEvent] = []
        
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging handlers"""
        self.logger = logging.getLogger("AuditLogger")
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def log_event(self, event: AuditEvent) -> None:
        """Log a structured audit event"""
        #souvgarde en ram pour garder tout en mémoire pendant que le programme tourne
        self.events_log.append(event)
        #souvgarde dans le fichier de log textuel
        self.logger.log(
            self._severity_to_log_level(event.severity),
            self._format_event_message(event)
        )
        
        self._write_json_log(event)

    def _format_event_message(self, event: AuditEvent) -> str:
        """Format event for text log"""
        parts = [
            f"[{event.event_type}]",
            f"User: {event.user}" if event.user else "",
            f"Resource: {event.resource}" if event.resource else "",
            f"Action: {event.action}" if event.action else "",
            f"Result: {event.result}" if event.result else "",
        ]
        return " | ".join([p for p in parts if p])

    def _severity_to_log_level(self, severity: str) -> int:
        """Convert severity string to logging level"""
        mapping = {
            SeverityLevel.INFO.value: logging.INFO, #logging.info==20 
            SeverityLevel.WARNING.value: logging.WARNING,#logging.warning==30
            SeverityLevel.CRITICAL.value: logging.CRITICAL,#logging.critical==50
            SeverityLevel.ALERT.value: logging.CRITICAL,#==50 pas critical dans python logging
        }
        return mapping.get(severity, logging.INFO)

    def _write_json_log(self, event: AuditEvent) -> None:
        """Append event to JSON log file"""
        try:
            events = []
            if os.path.exists(self.json_log_file):
                with open(self.json_log_file, 'r') as f:
                    events = json.load(f)
            
            events.append(asdict(event))
            
            with open(self.json_log_file, 'w') as f:
                json.dump(events, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to write JSON log: {str(e)}")

    def log_login_attempt(self, username: str, ip_address: Optional[str] = None) -> None:
        """Log login attempt"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.LOGIN_ATTEMPT.value,
            severity=SeverityLevel.INFO.value,
            user=username,
            action="LOGIN"
        )
        self.log_event(event)

    def log_login_success(self, username: str, ip_address: Optional[str] = None,
                         session_id: Optional[str] = None) -> None:
        """Log successful login"""
        self.failed_login_attempts[username] = 0
        
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.LOGIN_SUCCESS.value,
            severity=SeverityLevel.INFO.value,
            user=username,
            action="LOGIN",
            result="SUCCESS"
        )
        self.log_event(event)

    def log_login_failure(self, username: str, reason: str, 
                         ip_address: Optional[str] = None) -> None:
        """Log failed login and detect brute force"""
        self.failed_login_attempts[username] = self.failed_login_attempts.get(username, 0) + 1
        
        severity = SeverityLevel.WARNING.value
        event_type = AuditEventType.LOGIN_FAILURE.value
        
        if self.failed_login_attempts[username] >= self.suspicious_threshold:
            severity = SeverityLevel.ALERT.value
        
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            severity=severity,
            user=username,
            action="LOGIN",
            result="FAILURE",
            error_message=reason,
            details={"failed_attempts": self.failed_login_attempts[username]}
        )
        self.log_event(event)

    def log_tgt_issued(self, username: str, tgt_id: str, 
                      expiration: str) -> None:
        """Log TGT issuance"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.TGT_ISSUED.value,
            severity=SeverityLevel.INFO.value,
            user=username,
            action="TGT_ISSUE",
            result="SUCCESS",
            details={"tgt_id": tgt_id, "expiration": expiration}
        )
        self.log_event(event)

    def log_service_ticket_issued(self, username: str, service: str,
                                 ticket_id: str, expiration: str) -> None:
        """Log service ticket issuance"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.SERVICE_TICKET_ISSUED.value,
            severity=SeverityLevel.INFO.value,
            user=username,
            action="SERVICE_TICKET_ISSUE",
            result="SUCCESS",
            details={"ticket_id": ticket_id, "expiration": expiration}
        )
        self.log_event(event)

    def log_access_allowed(self, username: str, resource: str, action: str,
                          details: Optional[Dict[str, Any]] = None) -> None:
        """Log allowed access"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.ACCESS_ALLOWED.value,
            severity=SeverityLevel.INFO.value,
            user=username,
            resource=resource,
            action=action,
            result="ALLOW",
            details=details
        )
        self.log_event(event)

    def log_access_denied(self, username: str, resource: str, action: str,
                         reason: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Log denied access"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.ACCESS_DENIED.value,
            severity=SeverityLevel.WARNING.value,
            user=username,
            resource=resource,
            action=action,
            result="DENY",
            error_message=reason,
            details=details
        )
        self.log_event(event)

    def log_replay_attack_detected(self, username: Optional[str],
                                  nonce: str, ip_address: Optional[str] = None) -> None:
        """Log detected replay attack"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.REPLAY_ATTACK_DETECTED.value,
            severity=SeverityLevel.CRITICAL.value,
            user=username,
            action="REPLAY_ATTACK",
            result="DETECTED",
            details={"nonce": nonce}
        )
        self.log_event(event)

    def log_ticket_tampering_detected(self, username: Optional[str],
                                     ticket_id: str, reason: str) -> None:
        """Log detected ticket tampering"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.TICKET_TAMPERING_DETECTED.value,
            severity=SeverityLevel.CRITICAL.value,
            user=username,
            action="TICKET_TAMPERING",
            result="DETECTED",
            error_message=reason,
            details={"ticket_id": ticket_id}
        )
        self.log_event(event)

    def log_privilege_escalation_attempt(self, username: str, 
                                        requested_role: str,
                                        current_role: str) -> None:
        """Log privilege escalation attempt"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.PRIVILEGE_ESCALATION_ATTEMPT.value,
            severity=SeverityLevel.CRITICAL.value,
            user=username,
            action="PRIVILEGE_ESCALATION",
            result="ATTEMPT",
            details={
                "requested_role": requested_role,
                "current_role": current_role
            }
        )
        self.log_event(event)

    def log_unauthorized_access_attempt(self, username: str, resource: str,
                                       reason: str) -> None:
        """Log unauthorized access attempt"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT.value,
            severity=SeverityLevel.ALERT.value,
            user=username,
            resource=resource,
            action="UNAUTHORIZED_ACCESS",
            result="BLOCKED",
            error_message=reason
        )
        self.log_event(event)

    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_events": len(self.events_log),
            "critical_events": len([e for e in self.events_log if e.severity == SeverityLevel.CRITICAL.value]),
            "failed_logins": dict(self.failed_login_attempts),
            "access_events": len([e for e in self.events_log if "ACCESS" in e.event_type])
        }


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def initialize_audit_logger(log_file: str = "audit.log",
                           json_log_file: str = "audit_events.json") -> AuditLogger:
    """Initialize audit logger with custom paths"""
    global _audit_logger
    _audit_logger = AuditLogger(log_file, json_log_file)
    return _audit_logger