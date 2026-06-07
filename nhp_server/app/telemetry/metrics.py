"""Telemetry: Prometheus metrics collection."""

from __future__ import annotations

import logging
from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger(__name__)

# Counters
KNK_SUBMITTED = Counter(
    "nhp_knk_submitted_total",
    "Total KNK payloads submitted",
    ["node_id"],
)
KNK_APPROVED = Counter(
    "nhp_knk_approved_total",
    "Total KNK payloads approved",
    ["node_id"],
)
KNK_REJECTED = Counter(
    "nhp_knk_rejected_total",
    "Total KNK payloads rejected",
    ["node_id", "reason"],
)

# Gauges
ACTIVE_SESSIONS = Gauge(
    "nhp_active_sessions",
    "Currently active NHP sessions",
)
TRUSTED_KEYS = Gauge(
    "nhp_trusted_keys",
    "Number of trusted public keys in store",
)

# Histograms
VALIDATION_LATENCY = Histogram(
    "nhp_validation_latency_seconds",
    "Time to validate a KNK payload",
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
POLICY_EVALUATION_LATENCY = Histogram(
    "nhp_policy_evaluation_latency_seconds",
    "Time for full policy evaluation",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)
MAMA_GATE_SCORE = Histogram(
    "nhp_mama_gate_score",
    "MAMA gate evaluation scores",
    buckets=[0.1, 0.2, 0.3, 0.5, 0.7, 0.85, 0.95, 1.0],
    ["gate_name"],
)
