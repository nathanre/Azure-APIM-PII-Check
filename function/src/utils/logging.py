"""Structured JSON logging configured for Application Insights ingestion.

Logs are emitted as single-line JSON objects so App Insights (and any log
pipeline) can parse ``customDimensions`` reliably. Raw prompt or document
content is never logged unless ``LOG_RAW_CONTENT`` is explicitly enabled.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict, Optional

_CONFIGURED = False
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName",
}


class JsonFormatter(logging.Formatter):
    """Format log records as compact JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any structured extras attached to the record.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> None:
    """Install the JSON formatter on the root logger exactly once."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module logger, ensuring JSON logging is configured."""
    configure_logging()
    return logging.getLogger(name)


def log_event(
    logger: logging.Logger,
    level: int,
    message: str,
    correlation_id: Optional[str] = None,
    **fields: Any,
) -> None:
    """Emit a structured log event with a correlation id and extra fields."""
    extra: Dict[str, Any] = {"correlationId": correlation_id}
    extra.update(fields)
    logger.log(level, message, extra=extra)
