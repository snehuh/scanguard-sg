"""
ScanGuard SG — Flask backend entry point.

Security measures implemented here:
- CORS: restricted to registered origins only.
- Rate limiting: global 60/min; /api/check 20/min per IP.
- Security response headers on every reply.
- Request tracing via short UUID (returned only on 5xx for support).
- No URL or PII is ever logged; only verdict + score.
"""

import os
import uuid

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config
from modules.logger import get_logger
from modules.url_checker import check_url
from modules.validator import validate_url

logger = get_logger(__name__)


def create_app() -> Flask:
    app = Flask(__name__)
    cfg = get_config()
    app.config.from_object(cfg)

    # ── CORS ─────────────────────────────────────────────────────────────────
    CORS(app, origins=cfg.ALLOWED_ORIGINS, methods=["GET", "POST"])

    # ── Rate limiting ─────────────────────────────────────────────────────────
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[cfg.RATELIMIT_DEFAULT],
        storage_uri=cfg.RATELIMIT_STORAGE_URI,
    )

    # ── Security headers ─────────────────────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # X-XSS-Protection is intentionally omitted (deprecated; can introduce bugs)
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

    # ── Request tracing ───────────────────────────────────────────────────────
    @app.before_request
    def attach_request_id():
        g.request_id = uuid.uuid4().hex[:8]

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "version": "1.0.0"})

    @app.post("/api/check")
    @limiter.limit(cfg.RATELIMIT_SCAN)
    def check():
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            logger.warning("Rejected: missing/invalid JSON body [rid=%s]", g.request_id)
            return jsonify({"error": "Request body must be JSON."}), 400

        url = str(data.get("url", "")).strip()
        ok, error_msg = validate_url(url)
        if not ok:
            return jsonify({"error": error_msg}), 422

        try:
            result = check_url(url)
            return jsonify(result)
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("URL analysis returned unexpected data [rid=%s]: %s", g.request_id, exc)
            return jsonify({"error": "Analysis failed. Please try again.", "request_id": g.request_id}), 500
        except Exception:
            # Catch-all for truly unexpected failures; log full traceback server-side
            logger.error(
                "Unhandled error during URL check [rid=%s]",
                g.request_id,
                exc_info=True,
            )
            return jsonify(
                {
                    "error": "Analysis failed. Please try again.",
                    "request_id": g.request_id,
                }
            ), 500

    @app.errorhandler(429)
    def ratelimit_exceeded(_e):
        logger.warning("Rate limit exceeded [rid=%s]", g.request_id)
        return (
            jsonify({"error": "Too many requests. Please wait before trying again."}),
            429,
        )

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"error": "Method not allowed."}), 405

    return app


if __name__ == "__main__":
    application = create_app()
    port = int(os.environ.get("PORT", 5000))
    application.run(host="0.0.0.0", port=port, debug=application.config.get("DEBUG"))
