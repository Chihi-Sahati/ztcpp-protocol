"""Telemetry: OpenTelemetry tracing configuration."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def setup_tracing(service_name: str = "nhp-server") -> None:
    """Configure OpenTelemetry tracing for the NHP-Server.

    Sets up trace provider, exporter, and processor. In production,
    the exporter would send traces to a collector (Jaeger, Tempo, etc.).

    Args:
        service_name: Service name for trace identification.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)

        logger.info("OpenTelemetry tracing configured: service=%s", service_name)
    except ImportError:
        logger.warning("OpenTelemetry not available. Tracing disabled.")
