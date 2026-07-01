"""EDNS Metrics computation and evaluation module.

Expected Demand Not Served (EDNS) is a key metric in the NHP-SBA protocol
that quantifies the projected demand that would remain unmet if the
requested operation were allowed to proceed. A higher EDNS score indicates
greater potential disruption to network services.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EDNSInput:
    """Input parameters for EDNS score computation."""

    current_capacity_utilization: float
    projected_demand_increase: float
    sla_breach_risk: float
    historical_sla_compliance: float
    network_congestion_index: float


class EDNSCalculator:
    """Computes the Expected Demand Not Served (EDNS) score.

    The EDNS score is a composite metric calculated from multiple
    network performance indicators:

    EDNS = 0.35 * capacity_pressure
         + 0.25 * demand_surge
         + 0.20 * sla_risk
         + 0.10 * compliance_deficit
         + 0.10 * congestion_factor

    Where:
    - capacity_pressure = current_utilization + projected_demand_increase
    - demand_surge = projected_demand_increase
    - sla_risk = sla_breach_risk
    - compliance_deficit = 1.0 - historical_sla_compliance
    - congestion_factor = network_congestion_index

    The resulting score is clamped to [0.0, 1.0].
    """

    WEIGHTS = {
        "capacity_pressure": 0.35,
        "demand_surge": 0.25,
        "sla_risk": 0.20,
        "compliance_deficit": 0.10,
        "congestion_factor": 0.10,
    }

    async def compute(self, input_data: EDNSInput) -> float:
        """Compute the EDNS score from input metrics.

        Args:
            input_data: Network performance indicators.

        Returns:
            EDNS score between 0.0 and 1.0.
        """
        capacity_pressure = min(1.0, input_data.current_capacity_utilization + input_data.projected_demand_increase)
        demand_surge = min(1.0, input_data.projected_demand_increase)
        sla_risk = min(1.0, input_data.sla_breach_risk)
        compliance_deficit = min(1.0, 1.0 - input_data.historical_sla_compliance)
        congestion_factor = min(1.0, input_data.network_congestion_index)

        edns = (
            self.WEIGHTS["capacity_pressure"] * capacity_pressure
            + self.WEIGHTS["demand_surge"] * demand_surge
            + self.WEIGHTS["sla_risk"] * sla_risk
            + self.WEIGHTS["compliance_deficit"] * compliance_deficit
            + self.WEIGHTS["congestion_factor"] * congestion_factor
        )

        edns = max(0.0, min(1.0, edns))

        logger.info(
            "EDNS computed: %.4f (capacity=%.3f, demand=%.3f, sla=%.3f, "
            "compliance=%.3f, congestion=%.3f)",
            edns, capacity_pressure, demand_surge, sla_risk,
            compliance_deficit, congestion_factor,
        )
        return edns

    def classify_risk(self, edns_score: float) -> str:
        """Classify the risk level based on EDNS score.

        Args:
            edns_score: EDNS score (0.0-1.0).

        Returns:
            Risk classification: 'low', 'medium', 'high', 'critical'.
        """
        if edns_score < 0.25:
            return "low"
        elif edns_score < 0.50:
            return "medium"
        elif edns_score < 0.75:
            return "high"
        return "critical"
