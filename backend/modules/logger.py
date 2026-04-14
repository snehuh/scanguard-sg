"""
Structured, privacy-preserving logging.

Rules:
- Raw URLs are never written to logs (privacy by design).
- Only verdicts, scores, and anomaly signals are recorded.
- JSON lines format for easy ingestion by log aggregators.
"""

import logging
import sys
from datetime import datetime, timezone


class _JsonFormatter(logging.Formatter):
    """One JSON object per log line for structured log ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        return (
            f'{{"ts":"{datetime.now(timezone.utc).isoformat()}",'
            f'"level":"{record.levelname}",'
            f'"module":"{record.name}",'
            f'"msg":"{self._escape(record.getMessage())}"}}'
        )

    @staticmethod
    def _escape(text: str) -> str:
        return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger; idempotent (safe to call multiple times)."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
