"""
Singapore-specific threat detection.

Checks for:
1. Brand spoofing — local gov / bank / telco brands in the URL but on a
   non-official domain.
2. Scam-phrase patterns commonly seen in SG phishing messages.
"""

# ── Data ─────────────────────────────────────────────────────────────────────

# Brands that attackers most commonly impersonate in Singapore
_SG_BRANDS = [
    # Government / statutory boards
    "singpass", "myinfo", "cpf", "iras", "hdb", "moh", "mfa", "mas", "mom",
    "spf", "mccy", "imda", "nea", "pub", "lta", "jtc", "caas",
    # Banks
    "dbs", "posb", "ocbc", "uob", "maybank", "citibank", "hsbc",
    "stanchart", "standardchartered", "bankofchina",
    # Telcos & utilities
    "singtel", "starhub", "m1", "circles", "spgroup",
    # E-commerce / ride-hail
    "shopee", "lazada", "grab", "foodpanda", "gojek", "carousell",
    # Healthcare
    "singhealth", "nuhs", "ntuc", "fairprice",
]

# Scam trigger phrases in URLs
_SCAM_PHRASES = [
    "claim", "reward", "prize", "winner", "lucky-draw", "lucky_draw",
    "verify-account", "verify_account", "update-details", "update_details",
    "payment-failed", "payment_failed", "account-suspend", "reactivate",
    "gst-rebate", "gst_rebate", "gov-sg", "government-sg",
    "login-immediately", "urgent-action",
]

# Legitimate second-level domains for Singapore government / large brands
_OFFICIAL_SG_ROOTS = {
    ".gov.sg", ".edu.sg", ".com.sg", ".net.sg", ".org.sg",
}

# Exact hostnames considered authoritative (not exhaustive, extend as needed)
_OFFICIAL_HOSTNAMES = {
    "www.dbs.com.sg", "internet-banking.dbs.com.sg",
    "www.ocbc.com", "www.uob.com.sg",
    "www.singtel.com", "www.starhub.com",
    "www.cpf.gov.sg", "www.iras.gov.sg", "www.hdb.gov.sg",
    "www.singpass.gov.sg", "api.myinfo.gov.sg",
}


# ── Public API ────────────────────────────────────────────────────────────────

def detect(url: str, features: dict) -> dict:
    """
    Analyse a URL for SG-specific phishing signals.

    Returns:
        is_sg_targeted  – True if any known SG brand appears in the URL.
        brand_spoofed   – True if a brand appears but domain is unofficial.
        brands_found    – List of matched brand names (max 3).
        scam_phrases    – List of matched scam phrases (max 3).
    """
    url_lower = url.lower()
    hostname = features.get("hostname", "").lower()

    brands_found = [b for b in _SG_BRANDS if b in url_lower]

    brand_spoofed = False
    if brands_found:
        is_official_root = any(hostname.endswith(d) for d in _OFFICIAL_SG_ROOTS)
        is_official_host = hostname in _OFFICIAL_HOSTNAMES
        if not is_official_root and not is_official_host:
            brand_spoofed = True

    scam_phrases = [p for p in _SCAM_PHRASES if p in url_lower]

    return {
        "is_sg_targeted": bool(brands_found),
        "brand_spoofed": brand_spoofed,
        "brands_found": brands_found[:3],
        "scam_phrases": scam_phrases[:3],
    }
