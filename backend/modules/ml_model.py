"""
ML-ready risk scorer.

Current implementation: rule-based heuristic engine.

To upgrade to a real ML model:
  1. Collect a labelled dataset (PhishTank, OpenPhish, Tranco).
  2. Run feature_extractor.extract() + sg_detector.detect() on each row.
  3. Train a scikit-learn RandomForestClassifier on the feature vectors.
  4. Persist with: joblib.dump(model, 'model.pkl')
  5. Place model.pkl next to this file — it will be auto-loaded on startup.
"""

import logging
import os

from .logger import get_logger

logger = get_logger(__name__)

_MODEL = None
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model.pkl")


def _try_load_model() -> None:
    global _MODEL
    try:
        import joblib  # noqa: PLC0415 — optional dependency
        if os.path.exists(_MODEL_PATH):
            _MODEL = joblib.load(_MODEL_PATH)
            logger.info("Loaded trained ML model from model.pkl")
    except Exception as exc:  # noqa: BLE001
        logger.warning("ML model unavailable; using heuristic scorer: %s", exc)


_try_load_model()


# ── Risk weights ─────────────────────────────────────────────────────────────
# Each entry: (feature_key_or_callable, weight, human_reason)
# Weights are additive; final score is clamped to [0, 1].

_RULES: list[tuple] = [
    ("no_https",          0.15, "Connection is not encrypted (HTTP)"),
    ("has_ip_host",       0.35, "Uses a raw IP address instead of a domain name"),
    ("at_in_url",         0.35, "Contains '@' — possible URL-redirect trick"),
    ("double_slash",      0.20, "Double-slash redirect pattern detected"),
    ("long_url",          0.20, "Unusually long URL"),
    ("many_subdomains",   0.15, "Excessive number of subdomains"),
    ("hyphen_chain",      0.15, "Suspicious hyphen pattern in domain"),
    ("high_entropy",      0.10, "URL appears randomly generated"),
    ("is_shortener",      0.25, "URL shortener hides the real destination"),
    ("risky_tld",         0.20, "High-risk domain extension"),
    ("hex_encoding",      0.15, "Excessive percent-encoding in URL"),
    ("port_in_url",       0.10, "Non-standard port in URL"),
    ("brand_spoofed",     0.45, "Impersonates a trusted Singapore brand"),
    ("scam_phrases",      0.30, "Contains scam-related keywords"),
]


def score(features: dict, sg: dict) -> tuple[float, list[str]]:
    """
    Return (risk_score, reasons) where risk_score ∈ [0.0, 1.0].

    Delegates to the trained ML model when available; otherwise falls back to
    the heuristic engine.
    """
    if _MODEL is not None:
        return _ml_score(features, sg)
    return _heuristic_score(features, sg)


# ── Heuristic engine ──────────────────────────────────────────────────────────

def _heuristic_score(features: dict, sg: dict) -> tuple[float, list[str]]:
    flags = _build_flags(features, sg)
    total, reasons = 0.0, []
    for key, weight, reason in _RULES:
        if flags.get(key):
            total += weight
            reasons.append(_personalise(reason, sg))
    if not reasons:
        reasons.append("No suspicious patterns detected.")
    return min(total, 1.0), reasons


def _build_flags(f: dict, sg: dict) -> dict:
    return {
        "no_https":        not f.get("has_https", True),
        "has_ip_host":     f.get("has_ip_host", False),
        "at_in_url":       f.get("at_in_url", False),
        "double_slash":    f.get("double_slash_redirect", False),
        "long_url":        f.get("url_length", 0) > 100,
        "many_subdomains": f.get("subdomain_depth", 0) > 3,
        "hyphen_chain":    f.get("hyphen_count", 0) >= 3,
        "high_entropy":    f.get("entropy", 0) > 4.5,
        "is_shortener":    f.get("is_shortener", False),
        "risky_tld":       f.get("risky_tld", False),
        "hex_encoding":    f.get("hex_encoding", False),
        "port_in_url":     f.get("port_in_url", False),
        "brand_spoofed":   sg.get("brand_spoofed", False),
        "scam_phrases":    bool(sg.get("scam_phrases")),
    }


def _personalise(reason: str, sg: dict) -> str:
    if "brand" in reason and sg.get("brands_found"):
        return f"{reason}: {', '.join(sg['brands_found'])}"
    if "scam" in reason and sg.get("scam_phrases"):
        return f"{reason}: {', '.join(sg['scam_phrases'])}"
    return reason


# ── ML path ───────────────────────────────────────────────────────────────────

def _ml_score(features: dict, sg: dict) -> tuple[float, list[str]]:
    try:
        vec = _to_vector(features, sg)
        prob = float(_MODEL.predict_proba([vec])[0][1])
        return min(prob, 1.0), ["ML model assessment"]
    except Exception as exc:  # noqa: BLE001
        logger.error("ML scoring failed, falling back to heuristics: %s", exc)
        return _heuristic_score(features, sg)


def _to_vector(f: dict, sg: dict) -> list[float]:
    return [
        float(not f.get("has_https", True)),
        float(f.get("has_ip_host", False)),
        float(f.get("at_in_url", False)),
        float(f.get("double_slash_redirect", False)),
        min(f.get("url_length", 0) / 200.0, 1.0),
        min(f.get("subdomain_depth", 0) / 5.0, 1.0),
        min(f.get("hyphen_count", 0) / 5.0, 1.0),
        min(f.get("entropy", 0) / 6.0, 1.0),
        float(f.get("is_shortener", False)),
        float(f.get("risky_tld", False)),
        float(f.get("hex_encoding", False)),
        float(f.get("port_in_url", False)),
        float(sg.get("brand_spoofed", False)),
        float(bool(sg.get("scam_phrases"))),
    ]
