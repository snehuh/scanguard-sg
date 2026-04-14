"""
Input validation: URL format and SSRF-prevention.

Blocks:
- Non-HTTP(S) schemes
- Private / loopback / link-local addresses (SSRF)
- Excessively long inputs
"""

import re
from urllib.parse import urlparse

_MAX_LEN = 2048
_ALLOWED_SCHEMES = {"http", "https"}

# Patterns that indicate a private/internal address (SSRF prevention)
_PRIVATE_PATTERNS = [
    r"^localhost$",
    r"^127\.",
    r"^10\.",
    r"^172\.(1[6-9]|2\d|3[01])\.",
    r"^192\.168\.",
    r"^0\.",
    r"^169\.254\.",   # link-local
    r"^::1$",
    r"^fc[0-9a-fA-F]{2}:",  # ULA IPv6
    r"^fe80:",
    r"^0\.0\.0\.0$",
    r"^metadata\.google\.internal$",
]
_PRIVATE_RE = [re.compile(p, re.IGNORECASE) for p in _PRIVATE_PATTERNS]


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL before analysis.

    Returns (True, "") on success, or (False, <human-readable error>) on failure.
    """
    if not url:
        return False, "URL is required."
    if len(url) > _MAX_LEN:
        return False, f"URL must not exceed {_MAX_LEN} characters."

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL."

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, "Only HTTP and HTTPS URLs are supported."
    if not parsed.netloc:
        return False, "URL must include a valid domain."

    hostname = (parsed.hostname or "").lower()
    if _is_private(hostname):
        return False, "Cannot check internal or reserved addresses."

    return True, ""


def _is_private(hostname: str) -> bool:
    return any(rx.match(hostname) for rx in _PRIVATE_RE)
