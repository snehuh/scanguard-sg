"""
URL safety check pipeline.

Orchestrates: feature extraction → SG threat detection → risk scoring.
Returns a verdict dict that the API serialises directly to JSON.
"""

from .feature_extractor import extract
from .logger import get_logger
from .ml_model import score
from .sg_detector import detect

logger = get_logger(__name__)

_THRESHOLDS = {"safe": 0.30, "suspicious": 0.60}


def check_url(url: str) -> dict:
    """
    Full safety analysis of a URL.

    Returns:
        verdict       – "safe" | "suspicious" | "malicious"
        risk_score    – float in [0.0, 1.0]
        reasons       – list of human-readable explanations
        is_sg_targeted – whether known SG brands were detected
    """
    features = extract(url)
    sg = detect(url, features)
    risk_score, reasons = score(features, sg)
    verdict = _verdict(risk_score)

    # Log outcome only — never the URL itself (privacy)
    logger.info(
        "scan verdict=%s score=%.2f sg_targeted=%s",
        verdict, risk_score, sg["is_sg_targeted"],
    )

    return {
        "verdict": verdict,
        "risk_score": round(risk_score, 2),
        "reasons": reasons,
        "is_sg_targeted": sg["is_sg_targeted"],
    }


def _verdict(risk_score: float) -> str:
    if risk_score < _THRESHOLDS["safe"]:
        return "safe"
    if risk_score < _THRESHOLDS["suspicious"]:
        return "suspicious"
    return "malicious"
