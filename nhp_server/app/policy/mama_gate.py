"""MAMA Safety Gate deterministic evaluation engine.

Implements three mandatory safety gates that every NHP policy decision
must pass before approval:

1. Funding Gate: Ensures projected SLA penalty exposure and throughput
   deviation remain within acceptable financial thresholds.

2. Safety Gate: Verifies that the EDNS score and Capability Effectiveness
   Index (CEI) meet minimum safety requirements.

3. Value Realization Gate: Confirms that the projected value of the
   operation exceeds the projected cost (demand not served).

If ANY gate fails, the authorization is REJECTED and the caller MUST
trigger an immediate micro-tunnel teardown. This is a fail-closed design.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from app.models.policy import CEIMetrics, MAMAConfig, RejectionReason

logger = logging.getLogger(__name__)


class GateResult(str, Enum):
    """Result of a MAMA safety gate evaluation."""

    APPROVE = "approve"
    REJECT = "reject"


@dataclass(frozen=True)
class GateEvaluation:
    """Result of evaluating a single MAMA gate."""

    gate_name: str
    passed: bool
    rejection_reason: RejectionReason | None
    score: float
    threshold: float


class MAMASafetyGate:
    """Deterministic MAMA Safety Gate evaluator.

    Evaluates three gates in sequence. All three MUST pass for approval.
    If any gate fails, the result is immediate REJECT with the specific
    rejection reason, and the caller must initiate micro-tunnel teardown.

    The evaluation is fully deterministic - given the same inputs, it
    always produces the same output. No randomness or external state.
    """

    def __init__(self, config: MAMAConfig | None = None) -> None:
        """Initialize the MAMA Safety Gate with configuration.

        Args:
            config: MAMA configuration thresholds. Uses defaults if None.
        """
        self._config = config or MAMAConfig()
        logger.info(
            "MAMASafetyGate initialized. "
            "max_sla=%.2f, max_tp_dev=%.2f, min_fund=%.2f, min_safety=%.2f, min_val=%.2f",
            self._config.max_sla_penalty_exposure,
            self._config.max_throughput_deviation,
            self._config.min_funding_ratio,
            self._config.min_safety_score,
            self._config.min_value_realization,
        )

    async def evaluate(
        self,
        edns_score: float,
        cei_metrics: CEIMetrics,
        capabilities: list[str],
    ) -> tuple[GateResult, RejectionReason | None, list[GateEvaluation]]:
        """Evaluate all three MAMA safety gates deterministically.

        Args:
            edns_score: Expected Demand Not Served score (0.0-1.0).
            cei_metrics: Capability Effectiveness Index metrics.
            capabilities: List of requested capabilities.

        Returns:
            Tuple of (GateResult, optional RejectionReason, list of gate evaluations).
        """
        evaluations: list[GateEvaluation] = []

        # Gate 1: Funding Gate
        funding_result = self._evaluate_funding_gate(cei_metrics)
        evaluations.append(funding_result)
        if not funding_result.passed:
            logger.warning(
                "Funding Gate FAILED: reason=%s, score=%.4f, threshold=%.4f",
                funding_result.rejection_reason,
                funding_result.score,
                funding_result.threshold,
            )
            return (GateResult.REJECT, funding_result.rejection_reason, evaluations)

        # Gate 2: Safety Gate
        safety_result = self._evaluate_safety_gate(edns_score, cei_metrics)
        evaluations.append(safety_result)
        if not safety_result.passed:
            logger.warning(
                "Safety Gate FAILED: reason=%s, score=%.4f, threshold=%.4f",
                safety_result.rejection_reason,
                safety_result.score,
                safety_result.threshold,
            )
            return (GateResult.REJECT, safety_result.rejection_reason, evaluations)

        # Gate 3: Value Realization Gate
        value_result = self._evaluate_value_gate(cei_metrics)
        evaluations.append(value_result)
        if not value_result.passed:
            logger.warning(
                "Value Gate FAILED: reason=%s, score=%.4f, threshold=%.4f",
                value_result.rejection_reason,
                value_result.score,
                value_result.threshold,
            )
            return (GateResult.REJECT, value_result.rejection_reason, evaluations)

        logger.info(
            "All MAMA gates PASSED. edns=%.4f, cei=%.4f, caps=%s",
            edns_score,
            cei_metrics.capability_effectiveness_index,
            capabilities,
        )
        return (GateResult.APPROVE, None, evaluations)

    def _evaluate_funding_gate(self, cei: CEIMetrics) -> GateEvaluation:
        """Evaluate the Funding Safety Gate.

        Checks two conditions:
        1. SLA penalty exposure must not exceed max_sla_penalty_exposure.
        2. Throughput deviation must not exceed max_throughput_deviation.

        The gate also considers the funding ratio as a composite score:
        funding_ratio = 1.0 - max(sla_penalty_exposure, throughput_impact)

        Args:
            cei: Capability Effectiveness Index metrics.

        Returns:
            GateEvaluation with pass/fail result.
        """
        sla_check = cei.sla_penalty_exposure <= self._config.max_sla_penalty_exposure
        tp_check = cei.throughput_impact <= self._config.max_throughput_deviation

        composite_score = 1.0 - max(
            cei.sla_penalty_exposure,
            cei.throughput_impact,
        )

        if not sla_check:
            return GateEvaluation(
                gate_name="funding",
                passed=False,
                rejection_reason=RejectionReason.SLA_PENALTY_EXCEEDED,
                score=cei.sla_penalty_exposure,
                threshold=self._config.max_sla_penalty_exposure,
            )

        if not tp_check:
            return GateEvaluation(
                gate_name="funding",
                passed=False,
                rejection_reason=RejectionReason.THROUGHPUT_DEVIATION,
                score=cei.throughput_impact,
                threshold=self._config.max_throughput_deviation,
            )

        if composite_score < self._config.min_funding_ratio:
            return GateEvaluation(
                gate_name="funding",
                passed=False,
                rejection_reason=RejectionReason.FUNDING_EXCEEDED,
                score=composite_score,
                threshold=self._config.min_funding_ratio,
            )

        return GateEvaluation(
            gate_name="funding",
            passed=True,
            rejection_reason=None,
            score=composite_score,
            threshold=self._config.min_funding_ratio,
        )

    def _evaluate_safety_gate(
        self, edns_score: float, cei: CEIMetrics
    ) -> GateEvaluation:
        """Evaluate the Safety Gate.

        The composite safety score is computed as a weighted average:
        safety_score = 0.6 * (1.0 - edns_score) + 0.4 * cei.capability_effectiveness_index

        A higher EDNS score means MORE demand not served (worse).
        A higher CEI means MORE effective capabilities (better).

        Args:
            edns_score: Expected Demand Not Served (0.0-1.0).
            cei: Capability Effectiveness Index metrics.

        Returns:
            GateEvaluation with pass/fail result.
        """
        demand_safety = 1.0 - edns_score
        capability_safety = cei.capability_effectiveness_index
        safety_score = 0.6 * demand_safety + 0.4 * capability_safety

        if safety_score < self._config.min_safety_score:
            return GateEvaluation(
                gate_name="safety",
                passed=False,
                rejection_reason=RejectionReason.SAFETY_VIOLATION,
                score=safety_score,
                threshold=self._config.min_safety_score,
            )

        return GateEvaluation(
            gate_name="safety",
            passed=True,
            rejection_reason=None,
            score=safety_score,
            threshold=self._config.min_safety_score,
        )

    def _evaluate_value_gate(self, cei: CEIMetrics) -> GateEvaluation:
        """Evaluate the Value Realization Gate.

        Value realization = CEI - projected demand not served.
        This must be positive and above the minimum threshold.

        The idea is: if the capability effectiveness outweighs the
        projected unmet demand, the operation creates net positive value.

        Args:
            cei: Capability Effectiveness Index metrics.

        Returns:
            GateEvaluation with pass/fail result.
        """
        value_realization = (
            cei.capability_effectiveness_index - cei.projected_demand_not_served
        )

        if value_realization < self._config.min_value_realization:
            return GateEvaluation(
                gate_name="value_realization",
                passed=False,
                rejection_reason=RejectionReason.VALUE_NEGATIVE,
                score=value_realization,
                threshold=self._config.min_value_realization,
            )

        return GateEvaluation(
            gate_name="value_realization",
            passed=True,
            rejection_reason=None,
            score=value_realization,
            threshold=self._config.min_value_realization,
        )
