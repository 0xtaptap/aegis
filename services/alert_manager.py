"""
Crypto Guardian — Alert Manager
================================
Alert lifecycle management: dedup, cooldown, correlation, suppression, triage.

Before any alert reaches the user, it passes through:
  1. DEDUP — same finding within time window → suppress
  2. COOLDOWN — per-wallet rate limiting
  3. CORRELATION — group related findings into one alert
  4. TRIAGE — decide action: DISMISS / WATCH / ALERT_USER / BLOCK

Only ALERT_USER and BLOCK actions actually notify the user.
"""

import time
import sqlite3
import os
import hashlib
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ═══════════════════════════════════════════════════════════════

class AlertAction(str, Enum):
    DISMISS = "DISMISS"         # Drop silently — not worth attention
    WATCH = "WATCH"             # Log for record, don't notify user
    ALERT_USER = "ALERT_USER"   # Show to user
    BLOCK = "BLOCK"             # Critical — requires immediate action


@dataclass
class AlertDecision:
    """Result of triage — what to do with a finding."""
    action: AlertAction
    reason: str
    suppressed_by: Optional[str] = None  # Which rule suppressed it (dedup, cooldown, etc.)

    def to_dict(self) -> dict:
        d = {"action": self.action.value, "reason": self.reason}
        if self.suppressed_by:
            d["suppressedBy"] = self.suppressed_by
        return d


@dataclass
class ProcessedAlert:
    """An alert after it has been triaged."""
    wallet: str
    chain: str
    alert_type: str
    severity: str
    detail: str
    decision: AlertDecision
    confidence: float = 0.0
    findings: list = field(default_factory=list)  # Correlated findings
    tx_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "wallet": self.wallet,
            "chain": self.chain,
            "alertType": self.alert_type,
            "severity": self.severity,
            "detail": self.detail,
            "decision": self.decision.to_dict(),
            "confidence": round(self.confidence, 2),
            "findingCount": len(self.findings),
            "txHash": self.tx_hash,
            "timestamp": self.timestamp,
        }


# ═══════════════════════════════════════════════════════════════
# ALERT MANAGER
# ═══════════════════════════════════════════════════════════════

class AlertManager:
    """
    Central alert lifecycle manager.
    All alerts flow through here before reaching the user.
    """

    # Configurable thresholds
    DEDUP_WINDOW_SECONDS = 1800      # 30 min — same finding suppressed within this
    COOLDOWN_SECONDS = 600           # 10 min — per-wallet cooldown for LOW/MEDIUM
    MAX_ALERTS_PER_WALLET_HOUR = 5   # Rate limit per wallet
    MAX_ALERTS_TOTAL_HOUR = 20       # Global rate limit

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "alert_history.db"
            )
        self._db_path = db_path
        self._init_db()

        # In-memory counters (reset hourly)
        self._wallet_counts: dict[str, list[float]] = {}  # wallet -> [timestamps]
        self._total_timestamps: list[float] = []

        # Stats
        self._stats = {
            "total_processed": 0,
            "total_emitted": 0,
            "suppressed_dedup": 0,
            "suppressed_cooldown": 0,
            "suppressed_rate_limit": 0,
            "dismissed": 0,
            "watched": 0,
        }

    def _init_db(self):
        """Create alert history table for dedup tracking."""
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    wallet TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detail TEXT DEFAULT '',
                    action TEXT NOT NULL,
                    confidence REAL DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ah_fp ON alert_history(fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ah_wallet ON alert_history(wallet)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ah_ts ON alert_history(timestamp)")
            conn.commit()
            conn.close()
        except Exception as e:
            print("[AlertManager] DB init error: %s" % e)

    # ═══════════════════════════════════════════════════════════
    # MAIN ENTRY POINT
    # ═══════════════════════════════════════════════════════════

    def triage(self, wallet: str, chain: str, alert_type: str,
               severity: str, detail: str, confidence: float = 0.0,
               findings: list = None, tx_hash: str = "") -> ProcessedAlert:
        """
        Process a potential alert through the full pipeline:
        dedup → cooldown → rate limit → severity triage → decision.

        Returns a ProcessedAlert with the decision (DISMISS/WATCH/ALERT_USER/BLOCK).
        """
        self._stats["total_processed"] += 1
        now = time.time()
        wallet_lower = wallet.lower()

        # Generate fingerprint for dedup
        fingerprint = self._fingerprint(wallet_lower, chain, alert_type, detail)

        # ── Step 1: DEDUP ─────────────────────────────
        if self._is_duplicate(fingerprint, now):
            decision = AlertDecision(
                action=AlertAction.DISMISS,
                reason="Duplicate alert within %d min window" % (self.DEDUP_WINDOW_SECONDS // 60),
                suppressed_by="dedup",
            )
            self._stats["suppressed_dedup"] += 1
            return self._build_alert(
                wallet_lower, chain, alert_type, severity,
                detail, decision, confidence, findings or [], tx_hash, now
            )

        # ── Step 2: COOLDOWN ──────────────────────────
        # CRITICAL alerts bypass cooldown
        if severity != "CRITICAL" and self._is_in_cooldown(wallet_lower, now):
            decision = AlertDecision(
                action=AlertAction.WATCH,
                reason="Wallet in cooldown period — alert logged but not pushed",
                suppressed_by="cooldown",
            )
            self._stats["suppressed_cooldown"] += 1
            self._record_alert(fingerprint, wallet_lower, chain, alert_type,
                               severity, detail, "WATCH", confidence, now)
            return self._build_alert(
                wallet_lower, chain, alert_type, severity,
                detail, decision, confidence, findings or [], tx_hash, now
            )

        # ── Step 3: RATE LIMIT ────────────────────────
        if not self._check_rate_limit(wallet_lower, now):
            decision = AlertDecision(
                action=AlertAction.WATCH,
                reason="Rate limit reached (%d/wallet/hour or %d total/hour)" % (
                    self.MAX_ALERTS_PER_WALLET_HOUR, self.MAX_ALERTS_TOTAL_HOUR
                ),
                suppressed_by="rate_limit",
            )
            self._stats["suppressed_rate_limit"] += 1
            self._record_alert(fingerprint, wallet_lower, chain, alert_type,
                               severity, detail, "WATCH", confidence, now)
            return self._build_alert(
                wallet_lower, chain, alert_type, severity,
                detail, decision, confidence, findings or [], tx_hash, now
            )

        # ── Step 4: SEVERITY TRIAGE ───────────────────
        decision = self._severity_triage(severity, confidence, alert_type)

        # Record the alert
        self._record_alert(fingerprint, wallet_lower, chain, alert_type,
                           severity, detail, decision.action.value, confidence, now)

        # Track rate limit counters
        if decision.action in (AlertAction.ALERT_USER, AlertAction.BLOCK):
            self._stats["total_emitted"] += 1
            self._track_rate(wallet_lower, now)
        elif decision.action == AlertAction.WATCH:
            self._stats["watched"] += 1
        else:
            self._stats["dismissed"] += 1

        return self._build_alert(
            wallet_lower, chain, alert_type, severity,
            detail, decision, confidence, findings or [], tx_hash, now
        )

    # ═══════════════════════════════════════════════════════════
    # BATCH TRIAGE (for correlated findings)
    # ═══════════════════════════════════════════════════════════

    def triage_batch(self, wallet: str, chain: str,
                     findings: list[dict]) -> list[ProcessedAlert]:
        """
        Process multiple related findings for the same wallet/chain.
        Groups findings by target (contract address) and emits correlated alerts.
        """
        if not findings:
            return []

        # Group findings by target contract
        by_target: dict[str, list[dict]] = {}
        for f in findings:
            target = f.get("contract", f.get("target", f.get("token", "unknown")))
            if target not in by_target:
                by_target[target] = []
            by_target[target].append(f)

        results = []
        for target, group in by_target.items():
            # Pick the highest severity from the group
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            highest_severity = max(group, key=lambda f: severity_order.get(f.get("severity", "LOW"), 0))
            severity = highest_severity.get("severity", "MEDIUM")

            # Combine details
            if len(group) == 1:
                detail = group[0].get("detail", "")
                alert_type = group[0].get("type", "FINDING")
            else:
                types = [f.get("type", "") for f in group]
                detail = "%d findings on %s: %s" % (len(group), target[:12], ", ".join(types[:4]))
                alert_type = "CORRELATED_FINDINGS"

            # Average confidence
            confidences = [f.get("confidence", 0.5) for f in group]
            avg_confidence = sum(confidences) / len(confidences)

            alert = self.triage(
                wallet=wallet, chain=chain, alert_type=alert_type,
                severity=severity, detail=detail, confidence=avg_confidence,
                findings=group,
            )
            results.append(alert)

        return results

    # ═══════════════════════════════════════════════════════════
    # INTERNAL METHODS
    # ═══════════════════════════════════════════════════════════

    def _fingerprint(self, wallet: str, chain: str, alert_type: str, detail: str) -> str:
        """Generate a unique fingerprint for dedup."""
        # Use only the stable parts (not timestamps or exact amounts)
        raw = "%s:%s:%s:%s" % (wallet, chain, alert_type, detail[:80])
        return hashlib.md5(raw.encode()).hexdigest()

    def _is_duplicate(self, fingerprint: str, now: float) -> bool:
        """Check if this same alert was emitted recently."""
        try:
            conn = sqlite3.connect(self._db_path)
            cutoff = now - self.DEDUP_WINDOW_SECONDS
            row = conn.execute(
                "SELECT id FROM alert_history WHERE fingerprint = ? AND timestamp > ? "
                "AND action IN ('ALERT_USER', 'BLOCK') LIMIT 1",
                (fingerprint, cutoff)
            ).fetchone()
            conn.close()
            return row is not None
        except Exception:
            return False

    def _is_in_cooldown(self, wallet: str, now: float) -> bool:
        """Check if wallet is in cooldown (recently alerted)."""
        try:
            conn = sqlite3.connect(self._db_path)
            cutoff = now - self.COOLDOWN_SECONDS
            row = conn.execute(
                "SELECT id FROM alert_history WHERE wallet = ? AND timestamp > ? "
                "AND action IN ('ALERT_USER', 'BLOCK') LIMIT 1",
                (wallet, cutoff)
            ).fetchone()
            conn.close()
            return row is not None
        except Exception:
            return False

    def _check_rate_limit(self, wallet: str, now: float) -> bool:
        """Check rate limits. Returns True if within limits."""
        one_hour_ago = now - 3600

        # Clean old timestamps
        self._total_timestamps = [t for t in self._total_timestamps if t > one_hour_ago]
        if wallet in self._wallet_counts:
            self._wallet_counts[wallet] = [t for t in self._wallet_counts[wallet] if t > one_hour_ago]

        # Check global limit
        if len(self._total_timestamps) >= self.MAX_ALERTS_TOTAL_HOUR:
            return False

        # Check per-wallet limit
        wallet_ts = self._wallet_counts.get(wallet, [])
        if len(wallet_ts) >= self.MAX_ALERTS_PER_WALLET_HOUR:
            return False

        return True

    def _track_rate(self, wallet: str, now: float):
        """Record an emitted alert for rate limiting."""
        self._total_timestamps.append(now)
        if wallet not in self._wallet_counts:
            self._wallet_counts[wallet] = []
        self._wallet_counts[wallet].append(now)

    def _severity_triage(self, severity: str, confidence: float,
                         alert_type: str) -> AlertDecision:
        """
        Decide what action to take based on severity + confidence.
        This is the core decision logic.
        """

        # CRITICAL → always alert (confidence > 0.3 to avoid noise)
        if severity == "CRITICAL" and confidence >= 0.3:
            return AlertDecision(
                action=AlertAction.BLOCK,
                reason="Critical threat with %.0f%% confidence" % (confidence * 100),
            )

        # CRITICAL but low confidence → alert but don't block
        if severity == "CRITICAL" and confidence < 0.3:
            return AlertDecision(
                action=AlertAction.ALERT_USER,
                reason="Critical finding but low confidence (%.0f%%) — flagged for review" % (confidence * 100),
            )

        # HIGH + good confidence → alert
        if severity == "HIGH" and confidence >= 0.5:
            return AlertDecision(
                action=AlertAction.ALERT_USER,
                reason="High severity finding with %.0f%% confidence" % (confidence * 100),
            )

        # HIGH + low confidence → watch
        if severity == "HIGH" and confidence < 0.5:
            return AlertDecision(
                action=AlertAction.WATCH,
                reason="High severity but low confidence (%.0f%%) — monitoring" % (confidence * 100),
            )

        # MEDIUM → watch (don't spam)
        if severity == "MEDIUM":
            return AlertDecision(
                action=AlertAction.WATCH,
                reason="Medium severity — logged for context, not alerted",
            )

        # LOW/INFO → dismiss
        return AlertDecision(
            action=AlertAction.DISMISS,
            reason="Low severity — no action needed",
        )

    def _record_alert(self, fingerprint: str, wallet: str, chain: str,
                      alert_type: str, severity: str, detail: str,
                      action: str, confidence: float, timestamp: float):
        """Write to alert history DB."""
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO alert_history "
                "(fingerprint, wallet, chain, alert_type, severity, detail, action, confidence, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fingerprint, wallet, chain, alert_type, severity,
                 detail[:500], action, confidence, timestamp)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print("[AlertManager] Record error: %s" % e)

    def _build_alert(self, wallet, chain, alert_type, severity, detail,
                     decision, confidence, findings, tx_hash, timestamp) -> ProcessedAlert:
        """Build the final ProcessedAlert object."""
        return ProcessedAlert(
            wallet=wallet, chain=chain, alert_type=alert_type,
            severity=severity, detail=detail, decision=decision,
            confidence=confidence, findings=findings,
            tx_hash=tx_hash, timestamp=timestamp,
        )

    # ═══════════════════════════════════════════════════════════
    # STATS & HISTORY
    # ═══════════════════════════════════════════════════════════

    def get_stats(self) -> dict:
        """Get alert processing statistics."""
        return {
            **self._stats,
            "suppression_rate": round(
                (self._stats["suppressed_dedup"] + self._stats["suppressed_cooldown"]
                 + self._stats["suppressed_rate_limit"])
                / max(1, self._stats["total_processed"]) * 100, 1
            ),
        }

    def get_recent_alerts(self, wallet: str = None, limit: int = 20,
                          action_filter: str = None) -> list[dict]:
        """Get recent alert history from DB."""
        try:
            conn = sqlite3.connect(self._db_path)
            query = "SELECT wallet, chain, alert_type, severity, detail, action, confidence, timestamp FROM alert_history"
            params = []
            conditions = []

            if wallet:
                conditions.append("wallet = ?")
                params.append(wallet.lower())
            if action_filter:
                conditions.append("action = ?")
                params.append(action_filter)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            conn.close()

            return [{
                "wallet": r[0], "chain": r[1], "alertType": r[2],
                "severity": r[3], "detail": r[4], "action": r[5],
                "confidence": round(r[6], 2), "timestamp": r[7],
            } for r in rows]
        except Exception:
            return []

    def cleanup_old(self, max_age_days: int = 30):
        """Remove alert history older than max_age_days."""
        try:
            cutoff = time.time() - (max_age_days * 86400)
            conn = sqlite3.connect(self._db_path)
            conn.execute("DELETE FROM alert_history WHERE timestamp < ?", (cutoff,))
            conn.commit()
            conn.close()
        except Exception:
            pass
