"""
Crypto Guardian — Evidence-Based Confidence Scoring
====================================================
Replaces flat additive scoring (score += 20) with weighted evidence aggregation.

Each piece of evidence has:
  - source: where it came from (on_chain, simulation, database, heuristic, etc.)
  - weight: how reliable that source is (0.0 - 1.0)
  - finding_type: what was found
  - detail: human-readable explanation

Multiple evidence pieces are combined using weighted aggregation,
not simple addition.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# SOURCE RELIABILITY WEIGHTS
# ═══════════════════════════════════════════════════════════════

class EvidenceSource(str, Enum):
    """Where a piece of evidence came from."""
    ON_CHAIN_VERIFIED = "on_chain_verified"      # Bytecode analysis, on-chain state
    SIMULATION_RESULT = "simulation_result"       # Tx simulation via Alchemy
    SCAM_DB_CONFIRMED = "scam_db_confirmed"       # Seed data, confirmed by multiple sources
    SCAM_DB_COMMUNITY = "scam_db_community"       # Community-reported, unverified
    PROTOCOL_REGISTRY = "protocol_registry"       # Verified protocol match
    NAME_PATTERN = "name_pattern"                 # Regex match on token name
    HEURISTIC = "heuristic"                       # Logic-based rule (zero-count, nonce, etc.)
    AGE_BASED = "age_based"                       # Contract/token age analysis
    HOLDER_ANALYSIS = "holder_analysis"            # On-chain holder concentration
    RULES_ENGINE = "rules_engine"                  # Deterministic rule verdict


# Reliability weight per source — how much to trust this evidence
SOURCE_WEIGHTS: dict[EvidenceSource, float] = {
    EvidenceSource.ON_CHAIN_VERIFIED: 0.95,
    EvidenceSource.SIMULATION_RESULT: 0.85,
    EvidenceSource.SCAM_DB_CONFIRMED: 0.92,
    EvidenceSource.SCAM_DB_COMMUNITY: 0.50,
    EvidenceSource.PROTOCOL_REGISTRY: 0.95,
    EvidenceSource.NAME_PATTERN: 0.30,
    EvidenceSource.HEURISTIC: 0.40,
    EvidenceSource.AGE_BASED: 0.60,
    EvidenceSource.HOLDER_ANALYSIS: 0.70,
    EvidenceSource.RULES_ENGINE: 0.90,
}


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class Evidence:
    """A single piece of evidence supporting a threat assessment."""
    source: EvidenceSource
    finding_type: str
    detail: str
    severity: str = "MEDIUM"              # LOW, MEDIUM, HIGH, CRITICAL
    raw_score: int = 0                     # Original score (0-100) for backward compat
    is_positive: bool = False              # True = evidence of safety, False = evidence of threat

    @property
    def weight(self) -> float:
        """Get reliability weight for this evidence's source."""
        return SOURCE_WEIGHTS.get(self.source, 0.30)

    def to_dict(self) -> dict:
        return {
            "source": self.source.value,
            "findingType": self.finding_type,
            "detail": self.detail,
            "severity": self.severity,
            "weight": round(self.weight, 2),
            "isPositive": self.is_positive,
        }


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


@dataclass
class ConfidenceScore:
    """
    Aggregated confidence assessment from multiple pieces of evidence.
    """
    overall_score: int          # 0-100 (backward compatible with existing risk_score)
    confidence_level: ConfidenceLevel
    confidence_value: float     # 0.0 - 1.0 (how confident we are in the score)
    risk_level: str             # LOW, MEDIUM, HIGH, CRITICAL
    evidence_count: int
    primary_evidence: Optional[str] = None   # The strongest signal
    evidence_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overallScore": self.overall_score,
            "confidenceLevel": self.confidence_level.value,
            "confidenceValue": round(self.confidence_value, 2),
            "riskLevel": self.risk_level,
            "evidenceCount": self.evidence_count,
            "primaryEvidence": self.primary_evidence,
            "evidenceSources": self.evidence_sources,
        }


# ═══════════════════════════════════════════════════════════════
# CONFIDENCE CALCULATOR
# ═══════════════════════════════════════════════════════════════

class ConfidenceCalculator:
    """
    Aggregates multiple pieces of evidence into a single confidence-weighted score.

    Instead of:
        score += 20 (proxy)
        score += 40 (selfdestruct)
        score = min(score, 100)

    We now do:
        evidence = [
            Evidence(ON_CHAIN, "PROXY_CONTRACT", ..., raw_score=20),
            Evidence(ON_CHAIN, "SELFDESTRUCT", ..., raw_score=40),
        ]
        result = calculator.calculate(evidence)
        # result.overall_score = 55 (weighted, not simple addition)
        # result.confidence_level = HIGH (strong on-chain evidence)
    """

    def calculate(self, evidence_list: list[Evidence]) -> ConfidenceScore:
        """
        Calculate aggregated score from multiple evidence pieces.

        Uses weighted combination:
        1. Each evidence contributes: raw_score * source_weight
        2. Positive evidence (safety signals) reduces the score
        3. Confidence is based on the average weight of all evidence
        4. Multiple weak signals don't stack to 100 — diminishing returns
        """
        if not evidence_list:
            return ConfidenceScore(
                overall_score=0,
                confidence_level=ConfidenceLevel.LOW,
                confidence_value=0.0,
                risk_level="LOW",
                evidence_count=0,
            )

        threat_evidence = [e for e in evidence_list if not e.is_positive]
        safety_evidence = [e for e in evidence_list if e.is_positive]

        # Calculate threat score with diminishing returns
        if threat_evidence:
            # Sort by weighted contribution (strongest first)
            threat_evidence.sort(key=lambda e: e.raw_score * e.weight, reverse=True)

            # First evidence contributes fully, subsequent have diminishing impact
            weighted_score = 0.0
            decay = 1.0
            for e in threat_evidence:
                contribution = e.raw_score * e.weight * decay
                weighted_score += contribution
                decay *= 0.6  # Each additional signal contributes 60% of what it normally would

            threat_score = min(weighted_score, 100)
        else:
            threat_score = 0

        # Safety evidence reduces the score (but can't push below 0)
        safety_reduction = 0
        for e in safety_evidence:
            safety_reduction += e.raw_score * e.weight * 0.5  # Safety signals reduce by half their weight

        final_score = max(0, min(100, int(threat_score - safety_reduction)))

        # Confidence is the average source reliability of all evidence
        all_weights = [e.weight for e in evidence_list]
        avg_confidence = sum(all_weights) / len(all_weights)

        # Adjust confidence based on evidence count (more evidence = more confident)
        count_bonus = min(0.15, len(evidence_list) * 0.03)  # Up to +0.15 for 5+ pieces
        confidence_value = min(1.0, avg_confidence + count_bonus)

        # Find primary evidence (highest weighted contribution)
        all_sorted = sorted(evidence_list, key=lambda e: e.raw_score * e.weight, reverse=True)
        primary = all_sorted[0].finding_type if all_sorted else None

        # Unique sources
        sources = list(set(e.source.value for e in evidence_list))

        return ConfidenceScore(
            overall_score=final_score,
            confidence_level=self._value_to_level(confidence_value),
            confidence_value=confidence_value,
            risk_level=self._score_to_risk(final_score),
            evidence_count=len(evidence_list),
            primary_evidence=primary,
            evidence_sources=sources,
        )

    def _value_to_level(self, value: float) -> ConfidenceLevel:
        """Map confidence value to level."""
        if value >= 0.85:
            return ConfidenceLevel.VERY_HIGH
        if value >= 0.65:
            return ConfidenceLevel.HIGH
        if value >= 0.45:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def _score_to_risk(self, score: int) -> str:
        """Map score to risk level (backward compatible with existing system)."""
        if score < 20:
            return "LOW"
        if score < 50:
            return "MEDIUM"
        if score < 75:
            return "HIGH"
        return "CRITICAL"


# Module-level instance for convenience
confidence_calculator = ConfidenceCalculator()
