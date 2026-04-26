"""
Policy Decision Point (PDP) - Policy Engine for SecureCorp Zero-Trust System
Implements RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access Control).
Evaluates access requests and returns ALLOW/DENY decisions.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from audit_logger import get_audit_logger


class Decision(Enum):
    """Access decision types"""
    ALLOW = "ALLOW"
    DENY = "DENY"


class RoleBasedAccessControl:
    """RBAC Implementation - Controls access based on user roles."""

    def __init__(self):
        self.role_hierarchy = {
            "admin": ["admin", "manager", "employee"],
            "manager": ["manager", "employee"],
            "employee": ["employee"],
            "guest": []
        }
        self.permissions = {
            "admin": ["read", "write", "delete", "execute", "admin"],
            "manager": ["read", "write", "execute"],
            "employee": ["read"],
            "guest": []
        }
    

    def check_permission(self, role: str, action: str) -> bool:
        if role not in self.permissions:
            return False
        return action.lower() in self.permissions[role]

    def can_escalate_to_role(self, current_role: str, target_role: str) -> bool:
        if current_role not in self.role_hierarchy:
            return False
        return target_role in self.role_hierarchy[current_role]


class AttributeBasedAccessControl:
    """ABAC Implementation - Controls access based on user and resource attributes."""

    CLEARANCE_LEVELS = {
        "public": 1,
        "confidential": 2,
        "secret": 3,
        "top-secret": 4
    }
    


    def check_department_match(self, user_dept: str, resource_dept: str) -> bool:
        if user_dept.lower() == "it":
            return True
        return user_dept.lower() == resource_dept.lower()

    def check_clearance_level(self, user_clearance: str,
                              resource_classification: str) -> bool:
        user_level = self.CLEARANCE_LEVELS.get(user_clearance.lower(), 0)
        resource_level = self.CLEARANCE_LEVELS.get(resource_classification.lower(), 0)
        return user_level >= resource_level

    def check_location_access(self, user_location: str,
                              resource_access_location: str) -> bool:
        if resource_access_location.lower() == "any":
            return True
        if resource_access_location.lower() == "internal_only":
            return user_location.lower() == "internal"
        return True

    def check_time_based_access(self, allowed_hours: Optional[List[int]] = None) -> bool:
        if allowed_hours is None:
            return True
        current_hour = datetime.utcnow().hour
        return current_hour in allowed_hours


class PolicyEngine:
    """External Policy Engine - Loads and evaluates policies from JSON file."""

    def __init__(self, policies_file: str = "policies.json"):
        self.policies_file = policies_file
        self.policies = []
        self.load_policies()

    def load_policies(self):
        try:
            if not os.path.exists(self.policies_file):
                self.policies = []
                return False
            with open(self.policies_file, "r" , encoding="utf-8") as f:
                self.policies = json.load(f)
            self.policies.sort(key=lambda p: p.get("priority", 100))
            return True
        except Exception as e:
            self.policies = []
            return False
            
    
    def evaluate_condition(self, condition_key: str, condition_value: Any,
                           context: Dict[str, Any]) -> bool:
        try:
            parts = condition_key.split(".")
            value = context
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return False
            if isinstance(condition_value, list):
                return value in condition_value
            return value == condition_value
        except Exception:
            return False
    def evaluate_policy(self, policy: Dict[str, Any], context: Dict[str, Any]) -> str:
        conditions = policy.get("conditions", {})
        for cond_key, cond_value in conditions.items():
            if not self.evaluate_condition(cond_key, cond_value, context):
                return None
        return policy.get("effect", "DENY")
    
    def evaluate_policies(self, context: Dict[str, Any]) -> str:
        for policy in self.policies:
            if policy.get("effect") == "DENY":
                decision = self.evaluate_policy(policy, context)
                if decision == "DENY":
                    return "DENY"
        for policy in self.policies:
            if policy.get("effect") == "ALLOW":
                decision = self.evaluate_policy(policy, context)
                if decision == "ALLOW":
                    return "ALLOW"
        return "DENY"
        
                


class PolicyDecisionPoint:
    """Main PDP - Combines RBAC, ABAC, and external policies."""

    def __init__(self, policies_file: str = "policies.json"):
        self.rbac = RoleBasedAccessControl()
        self.abac = AttributeBasedAccessControl()
        self.policy_engine = PolicyEngine(policies_file)
        self.audit_logger = get_audit_logger()

    def make_decision(self,
                      user: Dict[str, Any],
                      resource: Dict[str, Any],
                      action: str,
                      environment: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
        if environment is None:
            environment = {}
        # journal de toutes les vérifications effectuées
        details = {"evaluated_checks": []}

        rbac_result = self.rbac.check_permission(user.get("role", "guest"), action)
        details["evaluated_checks"].append({
            "check": "RBAC",
            "result": rbac_result,
            "details": f"Role '{user.get('role')}' action '{action}'"
        })
        if not rbac_result:
            self.audit_logger.log_access_denied(user.get("id", "unknown"),
                                               resource.get("id", "unknown"),
                                               action,
                                               "RBAC permission denied",
                                               details)
            return "DENY", details

        dept_result = self.abac.check_department_match(user.get("department", "unknown"),
                                                       resource.get("department", "unknown"))
        details["evaluated_checks"].append({
            "check": "ABAC_Department",
            "result": dept_result
        })
        if not dept_result:
            self.audit_logger.log_access_denied(user.get("id", "unknown"),
                                               resource.get("id", "unknown"),
                                               action,
                                               "Department mismatch",
                                               details)
            return "DENY", details

        clearance_result = self.abac.check_clearance_level(user.get("clearance", "public"),
                                                           resource.get("classification", "public"))
        details["evaluated_checks"].append({
            "check": "ABAC_Clearance",
            "result": clearance_result
        })
        if not clearance_result:
            self.audit_logger.log_access_denied(user.get("id", "unknown"),
                                               resource.get("id", "unknown"),
                                               action,
                                               "Clearance insufficient",
                                               details)
            return "DENY", details

        location_result = self.abac.check_location_access(user.get("location", "internal"),
                                                          resource.get("access_location", "any"))
        details["evaluated_checks"].append({
            "check": "ABAC_Location",
            "result": location_result
        })
        if not location_result:
            self.audit_logger.log_access_denied(user.get("id", "unknown"),
                                               resource.get("id", "unknown"),
                                               action,
                                               "Location restricted",
                                               details)
            return "DENY", details

        time_result = self.abac.check_time_based_access(resource.get("allowed_hours"))
        details["evaluated_checks"].append({
            "check": "ABAC_Time",
            "result": time_result
        })
        if not time_result:
            self.audit_logger.log_access_denied(user.get("id", "unknown"),
                                               resource.get("id", "unknown"),
                                               action,
                                               "Time-based access denied",
                                               details)
            return "DENY", details

        context = {"user": user, "resource": resource, "environment": environment}
        policy_decision = self.policy_engine.evaluate_policies(context)
        details["evaluated_checks"].append({
            "check": "ExternalPolicies",
            "result": policy_decision == "ALLOW",
            "decision": policy_decision
        })
        if policy_decision == "DENY":
            self.audit_logger.log_access_denied(user.get("id", "unknown"),
                                               resource.get("id", "unknown"),
                                               action,
                                               "Policy engine denied access",
                                               details)
            return "DENY", details

        self.audit_logger.log_access_allowed(user.get("id", "unknown"),
                                            resource.get("id", "unknown"),
                                            action,
                                            details)
        return "ALLOW", details

    def detect_privilege_escalation(self, user: Dict[str, Any],
                                   requested_role: str) -> bool:
        current_role = user.get("role", "guest")
        if not self.rbac.can_escalate_to_role(current_role, requested_role):
            self.audit_logger.log_privilege_escalation_attempt(user.get("id", "unknown"),
                                                               requested_role,
                                                               current_role)
            return True
        return False