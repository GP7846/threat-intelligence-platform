"""
utils/validator.py — Input validation helpers.
Prevents garbage IPs and domains from entering the pipeline or firewall.
"""

import ipaddress
import re

# RFC-compliant domain regex
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# Private / reserved ranges — we never block these
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_valid_ip(value: str) -> bool:
    """
    Return True if `value` is a syntactically valid, non-private IP address.
    Accepts both IPv4 and IPv6.
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False

    # Reject loopback, private, link-local, multicast
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast:
        return False

    for network in _PRIVATE_NETWORKS:
        if addr in network:
            return False

    return True


def is_valid_domain(value: str) -> bool:
    """Return True if `value` looks like a valid public domain name."""
    value = value.strip().lower()
    if not value or len(value) > 253:
        return False
    return bool(_DOMAIN_RE.match(value))
