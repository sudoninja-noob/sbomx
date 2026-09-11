"""Structured logging setup.

Uses structlog when available, otherwise falls back to the stdlib logging
module so the tool never hard-fails on a missing optional dependency.
"""
from __future__ import annotations

import logging
import sys

try:
    import structlog  # type: ignore

    _HAVE_STRUCTLOG = True
except Exception:  # pragma: no cover - optional dep
    _HAVE_STRUCTLOG = False

_configured = False


def configure(json_logs: bool = False, level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    _configured = True

    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=lvl)

    if _HAVE_STRUCTLOG:
        renderer = (
            structlog.processors.JSONRenderer()
            if json_logs
            else structlog.dev.ConsoleRenderer(colors=False)
        )
        structlog.configure(
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                renderer,
            ],
            wrapper_class=structlog.make_filtering_bound_logger(lvl),
            logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
            cache_logger_on_first_use=True,
        )


def get_logger(name: str = "sbomx"):
    configure()
    if _HAVE_STRUCTLOG:
        return structlog.get_logger(name)
    return logging.getLogger(name)
