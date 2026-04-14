"""
URL feature extraction for risk scoring.

Extracts ~15 security-relevant signals from a URL.
All features are deterministic and require no external calls.
"""

import math
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

# Well-known URL shorteners whose destinations are hidden
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.io", "is.gd", "buff.ly", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "bl.ink", "snip.ly",
}

# TLDs frequently abused for free phishing domains
_RISKY_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".work", ".click", ".download", ".loan", ".men", ".win",
    ".review", ".cricket", ".science",
}


def extract(url: str) -> dict:
    """Return a feature dict for the given URL."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    return {
        "url_length": len(url),
        "has_https": parsed.scheme == "https",
        "has_ip_host": _is_ip(hostname),
        "at_in_url": "@" in url,
        "double_slash_redirect": url.count("//") > 1,
        "subdomain_depth": max(len(hostname.split(".")) - 2, 0),
        "hyphen_count": hostname.count("-"),
        "path_depth": len([p for p in path.split("/") if p]),
        "query_param_count": len(parse_qs(parsed.query)),
        "entropy": _shannon_entropy(url),
        "is_shortener": hostname in _SHORTENERS,
        "risky_tld": any(hostname.endswith(t) for t in _RISKY_TLDS),
        "hex_encoding": len(re.findall(r"%[0-9a-fA-F]{2}", url)) > 3,
        "port_in_url": parsed.port is not None,
        "hostname": hostname,
        "scheme": parsed.scheme,
    }


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_ip(hostname: str) -> bool:
    """Return True only for valid IPv4 addresses (each octet 0–255)."""
    try:
        import ipaddress  # noqa: PLC0415
        ipaddress.IPv4Address(hostname)
        return True
    except ValueError:
        return False


def _shannon_entropy(text: str) -> float:
    """Shannon entropy of *text* (higher → more random-looking)."""
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())
