"""
T2: Business Invariant Oracle
Defines rules that MUST hold true for the application. 
If an action violates these, it's a potential vulnerability.
"""
from __future__ import annotations
from typing import Any, Dict, List
from dataclasses import dataclass

@dataclass
class InvariantRule:
    name: str
    description: str
    condition: str  # Python expression evaluated against the context
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        try:
            # Safe evaluation of the invariant condition
            return bool(eval(self.condition, {}, context))
        except Exception:
            return False

class InvariantOracle:
    def __init__(self):
        self.rules: List[InvariantRule] = []
        self._register_default_rules()
        
    def _register_default_rules(self):
        self.rules.extend([
            InvariantRule(
                name="non_negative_cart",
                description="Cart total must be >= 0",
                condition="cart_total >= 0"
            ),
            InvariantRule(
                name="session_user_match",
                description="Requested user ID must match session user ID",
                condition="requested_user_id == session_user_id"
            ),
            InvariantRule(
                name="valid_coupon_usage",
                description="Coupon usage count must be <= 1",
                condition="coupon_usage_count <= 1"
            ),
            InvariantRule(
                name="auth_required_for_admin",
                description="Admin endpoints require admin role",
                condition="is_admin == True or not is_admin_endpoint"
            ),
            InvariantRule(
                name="no_privilege_escalation",
                description="User cannot arbitrarily change their own role",
                condition="user_role_change_allowed == False or new_role == old_role"
            )
        ])
        
    def add_rule(self, rule: InvariantRule):
        self.rules.append(rule)
        
    def evaluate_all(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        violations = []
        for rule in self.rules:
            if not rule.evaluate(context):
                violations.append({
                    "rule_name": rule.name,
                    "description": rule.description,
                    "condition": rule.condition
                })
        return violations
        
    def check_invariant(self, rule_name: str, context: Dict[str, Any]) -> bool:
        for rule in self.rules:
            if rule.name == rule_name:
                return rule.evaluate(context)
        return True