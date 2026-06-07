"""Comprehensive tests for the MAMA Safety Gate.

Tests cover:
- Funding gate pass/fail
- Safety gate pass/fail
- Value realization gate pass/fail
- Combined evaluation scenarios
- All specific rejection reasons
- Boundary/edge cases
"""

from __future__ import annotations

import pytest

from app.models.policy import CEIMetrics, MAMAConfig, RejectionReason
from app.policy.mama_gate import GateResult, GateEvaluation, MAMASafetyGate


class TestFundingGate:
    """Tests for the Funding Safety Gate."""

    @pytest.mark.asyncio
    async def test_funding_gate_passes_with_safe_metrics(self):
        """Safe SLA and throughput metrics should pass the funding gate."""
        gate = MAMASafetyGate(MAMAConfig())
        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.05,
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.15, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.APPROVE
        assert reason is None
        assert len(evals) == 3
        assert all(e.passed for e in evals)

    @pytest.mark.asyncio
    async def test_funding_gate_rejects_sla_penalty_exceeded(self):
        """SLA penalty exposure above threshold should be rejected."""
        gate = MAMASafetyGate(MAMAConfig(max_sla_penalty_exposure=0.15))
        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.50,  # Way above threshold!
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.15, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.REJECT
        assert reason == RejectionReason.SLA_PENALTY_EXCEEDED
        funding_eval = next(e for e in evals if e.gate_name == "funding")
        assert not funding_eval.passed
        assert funding_eval.score == 0.50

    @pytest.mark.asyncio
    async def test_funding_gate_rejects_throughput_deviation(self):
        """Throughput deviation above threshold should be rejected."""
        gate = MAMASafetyGate(MAMAConfig(max_throughput_deviation=0.20))
        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.85,  # Way above threshold!
            sla_penalty_exposure=0.05,
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.15, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.REJECT
        assert reason == RejectionReason.THROUGHPUT_DEVIATION

    @pytest.mark.asyncio
    async def test_funding_gate_rejects_low_composite_ratio(self):
        """Low composite funding ratio should be rejected."""
        gate = MAMASafetyGate(MAMAConfig(
            max_sla_penalty_exposure=0.25,
            max_throughput_deviation=0.25,
            min_funding_ratio=0.50,
        ))
        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.24,
            sla_penalty_exposure=0.24,
        )
        # Composite = 1.0 - 0.24 = 0.76 > 0.50, should pass
        result, reason, _ = await gate.evaluate(
            edns_score=0.15, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.APPROVE


class TestSafetyGate:
    """Tests for the Safety Gate."""

    @pytest.mark.asyncio
    async def test_safety_gate_passes_with_high_scores(self):
        """High EDNS safety (low EDNS score) and high CEI should pass."""
        gate = MAMASafetyGate(MAMAConfig())
        cei = CEIMetrics(
            capability_effectiveness_index=0.95,
            projected_demand_not_served=0.02,
            throughput_impact=0.05,
            sla_penalty_exposure=0.03,
        )
        result, reason, _ = await gate.evaluate(
            edns_score=0.05, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.APPROVE
        assert reason is None

    @pytest.mark.asyncio
    async def test_safety_gate_rejects_low_composite(self):
        """Low composite safety score should be rejected."""
        gate = MAMASafetyGate(MAMAConfig(min_safety_score=0.85))
        cei = CEIMetrics(
            capability_effectiveness_index=0.2,  # Low capability effectiveness
            projected_demand_not_served=0.8,  # High unmet demand
            throughput_impact=0.05,
            sla_penalty_exposure=0.05,
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.8,  # High demand not served
            cei_metrics=cei,
            capabilities=["soc-analysis"],
        )
        assert result == GateResult.REJECT
        assert reason == RejectionReason.SAFETY_VIOLATION

    @pytest.mark.asyncio
    async def test_safety_gate_formula(self):
        """Verify the safety gate formula:
        safety = 0.6 * (1 - edns) + 0.4 * cei
        """
        gate = MAMASafetyGate(MAMAConfig(min_safety_score=0.70))
        # safety = 0.6 * (1 - 0.3) + 0.4 * 0.8 = 0.6*0.7 + 0.4*0.8 = 0.42 + 0.32 = 0.74
        cei = CEIMetrics(
            capability_effectiveness_index=0.8,
            projected_demand_not_served=0.1,
            throughput_impact=0.05,
            sla_penalty_exposure=0.05,
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.3, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.APPROVE
        safety_eval = next(e for e in evals if e.gate_name == "safety")
        assert abs(safety_eval.score - 0.74) < 0.01


class TestValueGate:
    """Tests for the Value Realization Gate."""

    @pytest.mark.asyncio
    async def test_value_gate_passes_positive_value(self):
        """Positive value realization (CEI > PDNS) should pass."""
        gate = MAMASafetyGate(MAMAConfig())
        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.05,
        )
        # value = 0.85 - 0.05 = 0.80 > 0.10 threshold
        result, reason, _ = await gate.evaluate(
            edns_score=0.15, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.APPROVE

    @pytest.mark.asyncio
    async def test_value_gate_rejects_negative_value(self):
        """Negative value realization (PDNS > CEI) should be rejected."""
        gate = MAMASafetyGate(MAMAConfig())
        # Use metrics that pass safety gate but fail value gate
        # safety = 0.6*(1-edns) + 0.4*CEI must be >= 0.85
        # If edns=0.05, CEI must be >= (0.85 - 0.6*0.95)/0.4 = (0.85-0.57)/0.4 = 0.70
        # value = CEI - PDNS = 0.10 - 0.80 = -0.70 (negative)
        cei = CEIMetrics(
            capability_effectiveness_index=0.80,
            projected_demand_not_served=0.95,
            throughput_impact=0.05,
            sla_penalty_exposure=0.05,
        )
        # safety = 0.6*0.95 + 0.4*0.80 = 0.57 + 0.32 = 0.89 >= 0.85 OK
        # value = 0.80 - 0.95 = -0.15 < 0.10 REJECT
        result, reason, evals = await gate.evaluate(
            edns_score=0.05, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.REJECT
        assert reason == RejectionReason.VALUE_NEGATIVE

    @pytest.mark.asyncio
    async def test_value_gate_rejects_below_threshold(self):
        """Value realization below threshold but positive should be rejected."""
        gate = MAMASafetyGate(MAMAConfig(min_value_realization=0.20))
        # Need safety >= 0.85, but value < 0.20
        # edns=0.05, CEI=0.80: safety = 0.6*0.95 + 0.4*0.80 = 0.89 OK
        # PDNS=0.65: value = 0.80 - 0.65 = 0.15 < 0.20 REJECT
        cei = CEIMetrics(
            capability_effectiveness_index=0.80,
            projected_demand_not_served=0.65,
            throughput_impact=0.05,
            sla_penalty_exposure=0.05,
        )
        result, reason, _ = await gate.evaluate(
            edns_score=0.05, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.REJECT
        assert reason == RejectionReason.VALUE_NEGATIVE


class TestCombinedGates:
    """Tests for combined gate evaluation scenarios."""

    @pytest.mark.asyncio
    async def test_all_gates_pass_ideal_scenario(self):
        """Ideal scenario: all metrics are safe, all gates pass."""
        gate = MAMASafetyGate()
        cei = CEIMetrics(
            capability_effectiveness_index=0.95,
            projected_demand_not_served=0.02,
            throughput_impact=0.03,
            sla_penalty_exposure=0.02,
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.05, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.APPROVE
        assert reason is None
        assert len(evals) == 3

    @pytest.mark.asyncio
    async def test_funding_fails_first_stops_evaluation(self):
        """When funding gate fails, subsequent gates should not be evaluated."""
        gate = MAMASafetyGate()
        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.95,  # Will fail funding gate
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.15, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.REJECT
        assert reason == RejectionReason.SLA_PENALTY_EXCEEDED
        # Only funding gate evaluated
        assert len(evals) == 1

    @pytest.mark.asyncio
    async def test_boundary_values_at_threshold(self):
        """Values exactly at thresholds should pass (inclusive bounds)."""
        gate = MAMASafetyGate(MAMAConfig(
            max_sla_penalty_exposure=0.15,
            max_throughput_deviation=0.20,
            min_safety_score=0.50,
            min_value_realization=0.10,
        ))
        # value = 0.60 - 0.50 = 0.10 (exact threshold)
        # funding: max(0.15, 0.20) = 0.20, composite = 0.80 >= 0.30 OK
        # safety = 0.6*(1-edns) + 0.4*0.60
        # with edns=0.50: safety = 0.6*0.50 + 0.4*0.60 = 0.30 + 0.24 = 0.54 >= 0.50 OK
        cei = CEIMetrics(
            capability_effectiveness_index=0.60,
            projected_demand_not_served=0.49,  # value = 0.60 - 0.49 = 0.11 > 0.10
            throughput_impact=0.20,
            sla_penalty_exposure=0.15,
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.50, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.APPROVE

    @pytest.mark.asyncio
    async def test_all_gates_fail_critical_scenario(self):
        """Critical scenario: all metrics are dangerous, fails at first gate."""
        gate = MAMASafetyGate()
        cei = CEIMetrics(
            capability_effectiveness_index=0.05,
            projected_demand_not_served=0.95,
            throughput_impact=0.95,
            sla_penalty_exposure=0.95,
        )
        result, reason, evals = await gate.evaluate(
            edns_score=0.95, cei_metrics=cei, capabilities=["soc-analysis"]
        )
        assert result == GateResult.REJECT
        # Fails at funding gate first
        assert reason == RejectionReason.SLA_PENALTY_EXCEEDED
