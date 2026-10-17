"""
T1: FSM / State Machine
Supersedes/extends paramgraph.py to track application state, 
ephemeral tokens, and context across multi-step interactions.
"""
from __future__ import annotations
import re
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class ContextWallet:
    """Holds ephemeral state like cookies, headers, and tokens extracted from responses."""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    csrf_tokens: Dict[str, str] = field(default_factory=dict)

    def update_from_response(self, response_headers: Dict[str, str], response_body: str):
        # Extract cookies
        cookie_header = response_headers.get("set-cookie", "")
        if cookie_header:
            for chunk in cookie_header.split(","):
                if "=" in chunk:
                    name, _, rest = chunk.partition("=")
                    val = rest.split(";")[0].strip()
                    self.cookies[name.strip()] = val
        
        # Extract CSRF/Anti-forgery tokens from headers
        for header_name in ["x-csrf-token", "x-xsrf-token", "x-csrf"]:
            if header_name in response_headers:
                self.csrf_tokens[header_name] = response_headers[header_name]
                self.headers[header_name] = response_headers[header_name]
            
        # Extract CSRF from HTML meta tags
        match = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', response_body, re.IGNORECASE)
        if match:
            self.csrf_tokens["meta_csrf"] = match.group(1)
            
        # Extract JWT or session tokens from JSON responses
        if "application/json" in response_headers.get("content-type", "").lower():
            try:
                data = json.loads(response_body)
                for token_key in ["token", "access_token", "jwt", "session_id"]:
                    if token_key in data:
                        self.tokens[token_key] = str(data[token_key])
            except Exception:
                pass

@dataclass
class Transition:
    """Represents a state transition (an HTTP request/response pair)."""
    source_state: str
    target_state: str
    method: str
    url: str
    payload: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None

@dataclass
class AppState:
    """Represents the current state of the application during a scan."""
    name: str
    context_wallet: ContextWallet = field(default_factory=ContextWallet)
    variables: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    
    def record_action(self, method: str, url: str, status: int, response_body: str):
        self.history.append({
            "method": method,
            "url": url,
            "status": status,
            "body_length": len(response_body)
        })