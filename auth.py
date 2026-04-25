"""
Authentication Server (KDC) for SecureCorp Zero-Trust System
Handles login, TGT issuance, and service ticket generation.
Implements Kerberos-inspired authentication with replay protection.
"""

import hashlib
import hmac
import secrets
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import base64
from audit_logger import get_audit_logger 


class TicketType(Enum):
    """Ticket types"""
    TGT = "TGT"
    SERVICE = "SERVICE"


@dataclass
class Ticket:
    """Encrypted ticket structure"""
    ticket_type: str
    username: str
    service: Optional[str]
    issued_at: str
    expires_at: str
    nonce: str
    session_key: str
    attributes: Dict[str, Any]
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class CredentialStore:
    """Simple credential store"""
    
    def __init__(self):
        self.users = {
            "alice": {
                "password_hash": self._hash_password("password123"),
                "role": "admin",
                "department": "IT",
                "clearance": "top-secret",
                "location": "internal"
            },
            "bob": {
                "password_hash": self._hash_password("secure456"),
                "role": "manager",
                "department": "Finance",
                "clearance": "confidential",
                "location": "internal"
            },
            "charlie": {
                "password_hash": self._hash_password("access789"),
                "role": "employee",
                "department": "HR",
                "clearance": "public",
                "location": "internal"
            },
            "david": {
                "password_hash": self._hash_password("work101112"),
                "role": "employee",
                "department": "Operations",
                "clearance": "public",
                "location": "external"
            }
        }

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_credentials(self, username: str, password: str) -> bool:
        """Verify username and password"""
        if username not in self.users:
            return False
        user_data = self.users[username]
        return user_data["password_hash"] == self._hash_password(password)

    def get_user_attributes(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user attributes for ABAC"""
        #retourne le dictionnaire la case de username:
        return self.users.get(username)


class AuthenticationServer:
    """Kerberos-inspired Authentication Server (KDC)"""

    def __init__(self, master_key: str = "SECURECORP_MASTER_KEY_2026",
                 tgt_lifetime_minutes: int = 480,
                 ticket_lifetime_minutes: int = 60):
        """Initialize authentication server"""
        self.master_key = master_key
        self.tgt_lifetime = timedelta(minutes=tgt_lifetime_minutes)
        self.ticket_lifetime = timedelta(minutes=ticket_lifetime_minutes)
        self.credential_store = CredentialStore()
        self.audit_logger = get_audit_logger()
        self.issued_nonces = set()#contre replay attack
        self.blacklist_tokens = set()#invalid ticket avant expiration.

    def login(self, username: str, password: str, ip_address: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Authenticate user and issue TGT.
        Returns: (success, tgt_encrypted, error_message)
        """
        self.audit_logger.log_login_attempt(username, ip_address)
        
        if not self.credential_store.verify_credentials(username, password):
            error_msg = "Invalid credentials"
            self.audit_logger.log_login_failure(username, error_msg, ip_address)
            return False, None, error_msg

        try:
            tgt = self._generate_tgt(username)
            encrypted_tgt = self._encrypt_ticket(tgt)
            
            session_id = secrets.token_hex(16)
            self.audit_logger.log_login_success(username, ip_address, session_id)
            self.audit_logger.log_tgt_issued(username, tgt.nonce, tgt.expires_at)
            
            return True, encrypted_tgt, None
            
        except Exception as e:
            error_msg = f"TGT generation failed: {str(e)}"
            self.audit_logger.log_login_failure(username, error_msg, ip_address)
            return False, None, error_msg

    def request_service_ticket(self, username: str, service: str, 
                               tgt_encrypted: str, nonce: str,
                               ip_address: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Request service ticket using TGT.
        Implements replay protection.
        Returns: (success, service_ticket_encrypted, error_message)
        """
        try:
            # Validate nonce (replay protection)
            if nonce in self.issued_nonces:
                self.audit_logger.log_replay_attack_detected(username, nonce, ip_address)
                return False, None, "Replay attack detected: nonce already used"
            
            self.issued_nonces.add(nonce)
            
            # Decrypt and validate TGT
            tgt = self._decrypt_ticket(tgt_encrypted)
            if not tgt:
                return False, None, "Invalid or expired TGT"
            
            # Verify TGT signature
            if not self._verify_ticket_signature(tgt):
                self.audit_logger.log_ticket_tampering_detected(username, tgt.nonce, 
                                                                 "Invalid TGT signature")
                return False, None, "TGT signature verification failed"
            
            # Verify username matches
            if tgt.username != username:
                self.audit_logger.log_unauthorized_access_attempt(
                    username, service, "Username mismatch in TGT"
                )
                return False, None, "Username mismatch"
            
            # Check TGT expiration
            if datetime.fromisoformat(tgt.expires_at) < datetime.utcnow():
                return False, None, "TGT expired"
            
            # Generate service ticket
            service_ticket = self._generate_service_ticket(username, service, tgt)
            encrypted_ticket = self._encrypt_ticket(service_ticket)
            
            self.audit_logger.log_service_ticket_issued(
                username, service, service_ticket.nonce, service_ticket.expires_at
            )
            
            return True, encrypted_ticket, None
            
        except Exception as e:
            error_msg = f"Service ticket generation failed: {str(e)}"
            self.audit_logger.log_unauthorized_access_attempt(username, service, error_msg)
            return False, None, error_msg

    def _generate_tgt(self, username: str) -> Ticket:
        """Generate Ticket Granting Ticket"""
        user_attrs = self.credential_store.get_user_attributes(username)
        now = datetime.utcnow()
        
        tgt = Ticket(
            ticket_type=TicketType.TGT.value,
            username=username,
            service=None,
            issued_at=now.isoformat(),
            expires_at=(now + self.tgt_lifetime).isoformat(),
            nonce=secrets.token_hex(16),#anti replay attack
            session_key=secrets.token_hex(32),#chiffrement de communication de la session entre client et kdc
            attributes={
                "role": user_attrs.get("role"),
                "department": user_attrs.get("department"),
                "clearance": user_attrs.get("clearance"),
                "location": user_attrs.get("location")
            },
            signature=""
        )
        
        tgt.signature = self._sign_ticket(tgt)
        return tgt

    def _generate_service_ticket(self, username: str, service: str, 
                                 tgt: Ticket) -> Ticket:
        """Generate service ticket"""
        now = datetime.utcnow()
        
        ticket = Ticket(
            ticket_type=TicketType.SERVICE.value,
            username=username,
            service=service,
            issued_at=now.isoformat(),
            expires_at=(now + self.ticket_lifetime).isoformat(),
            nonce=secrets.token_hex(16),
            session_key=secrets.token_hex(32),
            attributes=tgt.attributes,
            signature=""
        )
        
        ticket.signature = self._sign_ticket(ticket)
        return ticket

    def _encrypt_ticket(self, ticket: Ticket) -> str:
        """Encrypt ticket (simplified with base64 and HMAC)"""
        ticket_json = ticket.to_json()
        
        ticket_b64 = base64.b64encode(ticket_json.encode()).decode()
        
        hmac_digest = hmac.new(
            self.master_key.encode(),
            ticket_b64.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{ticket_b64}.{hmac_digest}"

    def _decrypt_ticket(self, encrypted_ticket: str) -> Optional[Ticket]:
        """Decrypt and verify ticket"""
        try:
            parts = encrypted_ticket.split('.')
            if len(parts) != 2:
                return None
            
            ticket_b64, received_hmac = parts
            
            expected_hmac = hmac.new(
                self.master_key.encode(),
                ticket_b64.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(expected_hmac, received_hmac):
                return None
            
            ticket_json = base64.b64decode(ticket_b64).decode()
            ticket_dict = json.loads(ticket_json)
            
            return Ticket(**ticket_dict)
            
        except Exception:
            return None

    def _sign_ticket(self, ticket: Ticket) -> str:
        """Sign ticket Créer une empreinte unique du ticket qui prouve qu'il n'a pas été modifié."""
        payload = f"{ticket.username}:{ticket.ticket_type}:{ticket.issued_at}:{ticket.service}"
        signature = hmac.new(
            self.master_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def _verify_ticket_signature(self, ticket: Ticket) -> bool:
        """Verify ticket signature"""
        expected_sig = self._sign_ticket(ticket)
        return hmac.compare_digest(expected_sig, ticket.signature)

    def validate_service_ticket(self, service_ticket_encrypted: str, 
                               service: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate service ticket (called by resource servers)"""
        try:
            ticket = self._decrypt_ticket(service_ticket_encrypted)
            if not ticket:
                return False, None
            
            if not self._verify_ticket_signature(ticket):
                return False, None
            
            if ticket.service != service:
                return False, None
            
            if datetime.fromisoformat(ticket.expires_at) < datetime.utcnow():
                return False, None
            
            return True, ticket.to_dict()
            
        except Exception:
            return False, None

    def invalidate_token(self, token_nonce: str) -> None:
        """Add token to blacklist"""
        self.blacklist_tokens.add(token_nonce)

    def is_token_blacklisted(self, token_nonce: str) -> bool:
        """Check if token is blacklisted"""
        return token_nonce in self.blacklist_tokens


_kdc: Optional[AuthenticationServer] = None


def get_kdc() -> AuthenticationServer:
    """Get or create global KDC instance"""
    global _kdc
    if _kdc is None:
        _kdc = AuthenticationServer()
    return _kdc


def initialize_kdc(master_key: str = "SECURECORP_MASTER_KEY_2026") -> AuthenticationServer:
    """Initialize KDC with custom master key"""
    global _kdc
    _kdc = AuthenticationServer(master_key)
    return _kdc