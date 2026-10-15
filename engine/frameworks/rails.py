"""Ruby on Rails surface probes.

Rails mounts several dev-only routes behind a check on the environment.
If the app runs in development mode (or forgot to disable them), these
give attackers a route list, environment dump, and mailer preview.
"""
from ._probe import probe_specs


PROBES = [
    {
        "name": "rails_info_routes",
        "method": "GET",
        "path": "/rails/info/routes",
        "allow_html": True,
        "status_in": [200],
        "body_contains": ["Rails.application.routes", "Prefix"],
        "severity": "high",
        "reason": "Rails route list is exposed in the running app",
    },
    {
        "name": "rails_info_properties",
        "method": "GET",
        "path": "/rails/info/properties",
        "allow_html": True,
        "status_in": [200],
        "body_contains": ["Rails version", "Ruby version"],
        "severity": "medium",
        "reason": "Rails environment properties are exposed",
    },
    {
        "name": "rails_mailers",
        "method": "GET",
        "path": "/rails/mailers",
        "allow_html": True,
        "status_in": [200],
        "body_contains": ["Mailer Previews", "Email"],
        "severity": "high",
        "reason": "Rails mailer previews are exposed — can send real emails",
    },
    {
        "name": "rails_conductor",
        "method": "GET",
        "path": "/rails/conductor/action_mailbox/inbound_emails",
        "allow_html": True,
        "status_in": [200],
        "body_contains": ["Inbound Emails", "Action Mailbox"],
        "severity": "critical",
        "reason": ("Rails Action Mailbox conductor is exposed — inbound "
                   "email can be spoofed"),
    },
]


def scan(base_url, roe_guard=None, timeout=8, neg_fp=None):
    return probe_specs(base_url, PROBES, roe_guard=roe_guard, timeout=timeout,
                       neg_fp=neg_fp)


__all__ = ["scan", "PROBES"]
