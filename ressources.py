"""
Resource Server for SecureCorp Zero-Trust System
Validates service tickets, enforces access control, and manages resources.
"""

from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from auth import get_kdc
from pdp import PolicyDecisionPoint
from audit_logger import get_audit_logger


class ResourceServer:
    """Resource Server - Validates tickets and enforces access control."""

    def __init__(self):
        self.kdc = get_kdc()
        self.pdp = PolicyDecisionPoint()
        self.audit_logger = get_audit_logger()
        self.resources = {
            "1": {
                "id": "1",
                "name": "Financial Report Q1",
                "department": "Finance",
                "classification": "confidential",
                "access_location": "internal_only",
                "allowed_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                "content": "Sensitive financial data..."
            },
            "2": {
                "id": "2",
                "name": "Employee Handbook",
                "department": "HR",
                "classification": "public",
                "access_location": "any",
                "allowed_hours": None,
                "content": "Company policies and procedures..."
            },
            "3": {
                "id": "3",
                "name": "IT Security Policy",
                "department": "IT",
                "classification": "secret",
                "access_location": "internal_only",
                "allowed_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                "content": "Top-secret security protocols..."
            }
        }

    def validate_ticket_and_authorize(self, service_ticket: str, service: str,
                                     action: str, resource_id: str,
                                     ip_address: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validates service ticket and authorizes access.
        
        Args:
            service_ticket: Encrypted service ticket
            service: Target service name
            action: Action to perform (read, write, delete)
            resource_id: Resource identifier
            ip_address: Client IP address
            
        Returns:
            (authorized, resource_data, error_message)
        """
        try:
            # Step 1: Validate service ticket with KDC
            is_valid, ticket_data = self.kdc.validate_service_ticket(service_ticket, service)
            if not is_valid:
                self.audit_logger.log_ticket_validation_failure(
                    ticket_data.get("username") if ticket_data else None,
                    service,
                    "Invalid service ticket"
                )
                return False, None, "Invalid service ticket"

            # Step 2: Extract user attributes from ticket
            user = {
                "id": ticket_data.get("username"),
                "role": ticket_data.get("attributes", {}).get("role"),
                "department": ticket_data.get("attributes", {}).get("department"),
                "clearance": ticket_data.get("attributes", {}).get("clearance"),
                "location": ticket_data.get("attributes", {}).get("location")
            }

            # Step 3: Get resource attributes
            resource = self.resources.get(resource_id)
            if not resource:
                return False, None, "Resource not found"

            # Step 4: Call PDP for authorization decision
            environment = {"ip": ip_address, "time": datetime.utcnow().isoformat()}
            decision, details = self.pdp.make_decision(user, resource, action, environment)

            if decision == "ALLOW":
                return True, resource, None
            else:
                return False, None, "Access denied by policy"

        except Exception as e:
            error_msg = f"Authorization failed: {str(e)}"
            self.audit_logger.log_ticket_validation_failure(None, service, error_msg)
            return False, None, error_msg

    def get_resource(self, service_ticket: str, resource_id: str,
                    ip_address: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Get a resource (READ operation)."""
        return self.validate_ticket_and_authorize(service_ticket, "resource-server",
                                                 "read", resource_id, ip_address)

    def create_resource(self, service_ticket: str, resource_data: Dict[str, Any],
                       ip_address: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Create a new resource (WRITE operation)."""
        # For simplicity, we'll just authorize the write operation
        # In a real system, you'd validate the resource data and create it
        authorized, _, error = self.validate_ticket_and_authorize(
            service_ticket, "resource-server", "write", "new", ip_address
        )
        if authorized:
            # Create new resource with auto-generated ID
            new_id = str(len(self.resources) + 1)
            new_resource = {
                "id": new_id,
                "name": resource_data.get("name", "New Resource"),
                "department": resource_data.get("department", "General"),
                "classification": resource_data.get("classification", "public"),
                "access_location": resource_data.get("access_location", "any"),
                "allowed_hours": resource_data.get("allowed_hours"),
                "content": resource_data.get("content", "")
            }
            self.resources[new_id] = new_resource
            return True, new_resource, None
        return False, None, error

    def update_resource(self, service_ticket: str, resource_id: str,
                       resource_data: Dict[str, Any],
                       ip_address: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Update an existing resource (WRITE operation)."""
        authorized, resource, error = self.validate_ticket_and_authorize(
            service_ticket, "resource-server", "write", resource_id, ip_address
        )
        if authorized and resource:
            # Update resource data
            resource.update(resource_data)
            return True, resource, None
        return False, None, error

    def delete_resource(self, service_ticket: str, resource_id: str,
                       ip_address: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Delete a resource (DELETE operation)."""
        authorized, resource, error = self.validate_ticket_and_authorize(
            service_ticket, "resource-server", "delete", resource_id, ip_address
        )
        if authorized and resource:
            # Remove resource
            del self.resources[resource_id]
            return True, resource, None
        return False, None, error

    def list_resources(self, service_ticket: str,
                      ip_address: Optional[str] = None) -> Tuple[bool, Optional[List[Dict[str, Any]]], Optional[str]]:
        """List all accessible resources."""
        try:
            # Validate ticket first
            is_valid, ticket_data = self.kdc.validate_service_ticket(service_ticket, "resource-server")
            if not is_valid:
                return False, None, "Invalid service ticket"

            user = {
                "id": ticket_data.get("username"),
                "role": ticket_data.get("attributes", {}).get("role"),
                "department": ticket_data.get("attributes", {}).get("department"),
                "clearance": ticket_data.get("attributes", {}).get("clearance"),
                "location": ticket_data.get("attributes", {}).get("location")
            }

            # Filter resources user can access
            accessible_resources = []
            for resource_id, resource in self.resources.items():
                decision, _ = self.pdp.make_decision(user, resource, "read")
                if decision == "ALLOW":
                    accessible_resources.append(resource)

            return True, accessible_resources, None

        except Exception as e:
            return False, None, f"List resources failed: {str(e)}"


# Global resource server instance
_resource_server: Optional[ResourceServer] = None


def get_resource_server() -> ResourceServer:
    """Get or create global resource server instance"""
    global _resource_server
    if _resource_server is None:
        _resource_server = ResourceServer()
    return _resource_server