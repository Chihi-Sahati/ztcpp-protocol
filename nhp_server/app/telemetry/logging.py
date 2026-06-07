"""Telemetry: Structured logging configuration."""

from __future__ import annotations

import logging
import sys


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured logging using structlog.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
    """
    try:
        import structlog

        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, log_level.upper(), logging.INFO)
            ),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
            cache_logger_on_first_use=True,
        )
    except ImportError:
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            stream=sys.stdout,
        )
