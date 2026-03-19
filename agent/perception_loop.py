"""
Crypto Guardian — Perception Loop (v2)
The autonomous brain: continuously observes blockchain → triages → reasons → acts.

Intelligence Layer:
  - Observations are triaged: SAFE → dismiss, THREAT → auto-alert, AMBIGUOUS → LLM
  - Dedup via observation hashing (same wallet, same finding = skip)
  - LLM is fallback for genuinely ambiguous cases, not primary
  - AlertManager handles cooldown/dedup before user sees anything
"""

import os
import json
import time
import asyncio
import hashlib
import random
from typing import Optional


class PerceptionLoop:
    """
    Continuous observe → triage → think → act → evaluate loop.
    Runs as a background asyncio task, driven by GoalEngine goals.
    Uses triage to minimize LLM calls: only ambiguous findings go to the LLM.
    """

    def __init__(self, goal_engine, blockchain_service, threat_intel, memory_store,
                 monitor=None, alert_manager=None, rules_engine=None, interval: int = 120):
        self._goals = goal_engine
        self._bc = blockchain_service
        self._threat = threat_intel
        self._memory = memory_store
        self._monitor = monitor
        self._alert_mgr = alert_manager    # AlertManager for dedup/cooldown
        self._rules = rules_engine          # RulesEngine for fast-path decisions
        self._interval = interval
        self._running = False
        self._task = None
        self._agent_fn = None          # set by set_agent_fn()
        self._event_queue = asyncio.Queue()  # for event-driven triggers
        self._cycle_count = 0
        self._last_cycle_result = ""
        self._observation_hashes: dict[str, float] = {}  # hash -> last_seen timestamp
        self._llm_calls_total = 0
        self._llm_calls_skipped = 0

    def set_agent_fn(self, fn):
        """Set the async function to call the LangGraph agent brain.
        Expected signature: async fn(message: str, thread_id: str) -> dict
        """
        self._agent_fn = fn

    async def start(self):
        """Start the perception loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        print("[Perception] Autonomous loop started (every %ds)" % self._interval)

    async def stop(self):
        """Stop the perception loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print("[Perception] Autonomous loop stopped")

    def trigger_event(self, event_type: str, data: dict):
        """Push an event to wake up the perception loop immediately."""
        try:
            self._event_queue.put_nowait({
                "type": event_type, "data": data, "timestamp": time.time()
            })
        except asyncio.QueueFull:
            pass  # Drop event if queue is full

    async def _loop(self):
        """Main autonomous loop with triage architecture."""
        await asyncio.sleep(15)
        print("[Perception] First cycle starting...")

        while self._running:
            try:
                # Check for event-driven triggers (non-blocking)
                event = None
                try:
                    event = self._event_queue.get_nowait()
                    print("[Perception] Event trigger received: %s" % event.get("type", "unknown"))
                except asyncio.QueueEmpty:
                    pass

                goals = self._goals.get_active_goals()
                self._cycle_count += 1
                cycle_id = "cycle_%d_%d" % (self._cycle_count, int(time.time()))
                print("[Perception] ── Cycle #%d starting (%d goals, event=%s) ──" %
                      (self._cycle_count, len(goals), bool(event)))

                # ── OBSERVE ──
                observations = await self._observe(goals, event)

                # Also observe watchlist wallets from monitor
                if self._monitor:
                    try:
                        watchlist = self._monitor.get_watchlist()
                        if watchlist:
                            for entry in watchlist[:5]:
                                addr = entry.get("address", "")
                                chains = entry.get("chains", ["ethereum"])
                                obs = await self._observe_wallet(addr, chains)
                                observations.extend(obs)
                        recent_alerts = self._monitor.get_alerts(limit=5)
                        if recent_alerts:
                            observations.append({
                                "source": "monitor_alerts", "type": "recent_alerts",
                                "data": {"count": len(recent_alerts),
                                         "alerts": [a.get("alertType", "") for a in recent_alerts[:5]]},
                                "priority": 6,
                            })
                    except Exception as e:
                        print("[Perception] Monitor check error: %s" % e)

                # ── DEDUP ── Remove observations we've already seen recently
                fresh_observations = self._dedup_observations(observations)
                print("[Perception] Observed %d items (%d fresh, %d deduped)" % (
                    len(observations), len(fresh_observations),
                    len(observations) - len(fresh_observations)))

                # ── TRIAGE ── Split into SAFE / AMBIGUOUS / THREAT
                safe, ambiguous, threats = self._triage(fresh_observations)
                print("[Perception] Triage: %d safe (dismissed), %d ambiguous (LLM), %d threats (auto-alert)" % (
                    len(safe), len(ambiguous), len(threats)))

                # ── AUTO-ALERT threats (no LLM needed) ──
                for obs in threats:
                    await self._auto_alert(obs)

                # ── THINK + ACT on ambiguous only ──
                if ambiguous and self._agent_fn:
                    print("[Perception] Thinking about %d ambiguous observations..." % len(ambiguous))
                    result = await self._think_and_act(goals, ambiguous, event, cycle_id)
                    self._last_cycle_result = result.get("response", "")[:200]
                    self._llm_calls_total += 1
                    print("[Perception] Action taken: %s" % self._last_cycle_result[:100])
                elif event and self._agent_fn:
                    # Events always get LLM attention even if no ambiguous observations
                    result = await self._think_and_act(goals, fresh_observations, event, cycle_id)
                    self._last_cycle_result = result.get("response", "")[:200]
                    self._llm_calls_total += 1
                else:
                    self._llm_calls_skipped += 1
                    self._last_cycle_result = (
                        "Cycle #%d: %d safe (dismissed), %d threats (auto-alerted), "
                        "0 ambiguous — no LLM call needed"
                    ) % (self._cycle_count, len(safe), len(threats))

                # ── EVALUATE ──
                await self._evaluate(goals, fresh_observations, cycle_id)
                print("[Perception] ── Cycle #%d complete ──" % self._cycle_count)

            except Exception as e:
                print("[Perception] Loop error: %s" % e)
                import traceback
                traceback.print_exc()

            # Sleep with jitter (avoid thundering herd)
            if self._event_queue.empty():
                jitter = random.randint(-30, 30)
                await asyncio.sleep(max(30, self._interval + jitter))
            else:
                await asyncio.sleep(5)

    async def _observe(self, goals, event: Optional[dict] = None) -> list[dict]:
        """
        OBSERVE phase: gather blockchain state relevant to active goals.
        Returns list of observation dicts.
        """
        observations = []

        # If we have a triggered event, include it directly
        if event:
            observations.append({
                "source": "event_trigger",
                "type": event.get("type", "unknown"),
                "data": event.get("data", {}),
                "priority": 10,
            })

        for goal in goals:
            try:
                if goal.type.value == "sentinel":
                    # SENTINEL = do EVERYTHING
                    obs = await self._observe_sentinel(goal.chains)
                    observations.extend(obs)

                elif goal.type.value == "protect_wallet":
                    obs = await self._observe_wallet(goal.target, goal.chains)
                    observations.extend(obs)

                elif goal.type.value == "monitor_approvals":
                    obs = await self._observe_approvals(goal.target, goal.chains)
                    observations.extend(obs)

                elif goal.type.value == "hunt_scams":
                    obs = await self._observe_scam_activity(goal.chains)
                    observations.extend(obs)

                elif goal.type.value == "track_threats":
                    obs = await self._observe_threats()
                    observations.extend(obs)

                elif goal.type.value == "guard_portfolio":
                    obs = await self._observe_portfolio(goal.target, goal.chains)
                    observations.extend(obs)

            except Exception as e:
                observations.append({
                    "source": "error", "type": "observation_failed",
                    "data": {"goal": goal.id, "error": str(e)}, "priority": 3,
                })

        return observations

    async def _observe_wallet(self, address: str, chains: list[str]) -> list[dict]:
        """Observe a wallet for new activity."""
        obs = []
        for chain in chains:
            try:
                txs = await self._bc.get_transactions(address, chain)
                recent = [t for t in (txs or []) if t.get("direction") == "OUT"][:5]
                if recent:
                    obs.append({
                        "source": "wallet_monitor", "type": "recent_outflows",
                        "data": {"address": address[:10], "chain": chain,
                                 "count": len(recent), "txs": recent[:3]},
                        "priority": 5,
                    })

                # Check against scam DB
                if self._threat and hasattr(self._threat, 'scam_db'):
                    for tx in recent[:3]:
                        to_addr = tx.get("to", "")
                        if to_addr:
                            scam_hit = self._threat.scam_db.is_known_scam(to_addr)
                            if scam_hit:
                                obs.append({
                                    "source": "scam_db", "type": "SCAM_INTERACTION",
                                    "data": {"wallet": address[:10], "scam_address": to_addr[:10],
                                             "category": scam_hit.get("category", "unknown"),
                                             "reason": scam_hit.get("reason", "")},
                                    "priority": 10,
                                })
            except Exception:
                pass
        return obs

    async def _observe_approvals(self, address: str, chains: list[str]) -> list[dict]:
        """Check for risky approvals on watched wallets."""
        obs = []
        for chain in chains:
            try:
                approvals = await self._bc.get_approvals(address, chain)
                risky = [a for a in (approvals or []) if a.get("riskLevel") in ("HIGH", "CRITICAL")]
                if risky:
                    obs.append({
                        "source": "approval_scanner", "type": "risky_approvals",
                        "data": {"address": address[:10], "chain": chain,
                                 "count": len(risky), "approvals": risky[:3]},
                        "priority": 7,
                    })
            except Exception:
                pass
        return obs

    async def _observe_scam_activity(self, chains: list[str]) -> list[dict]:
        """Proactively check for new scam patterns."""
        obs = []
        if self._threat and hasattr(self._threat, 'scam_db'):
            stats = self._threat.scam_db.get_stats()
            obs.append({
                "source": "scam_db", "type": "scam_db_status",
                "data": {"total_known": stats.get("total", 0),
                         "community_reports": stats.get("community_reports", 0),
                         "categories": stats.get("categories", {})},
                "priority": 5,
            })
        return obs

    async def _observe_threats(self) -> list[dict]:
        """Check for active threat patterns from monitor history."""
        obs = []
        # Pull recent alerts from memory if we have them
        if self._memory:
            recent_incidents = self._memory.get_incidents(limit=5)
            if recent_incidents:
                obs.append({
                    "source": "memory", "type": "recent_threat_history",
                    "data": {"count": len(recent_incidents),
                             "types": [i.get("type", "") for i in recent_incidents],
                             "latest": recent_incidents[0] if recent_incidents else {}},
                    "priority": 5,
                })
        return obs

    async def _observe_sentinel(self, chains: list[str]) -> list[dict]:
        """SENTINEL mode: combine ALL observation types into one comprehensive sweep."""
        obs = []
        obs.extend(await self._observe_scam_activity(chains))
        obs.extend(await self._observe_threats())
        if self._monitor:
            try:
                watchlist = self._monitor.get_watchlist()
                for entry in watchlist[:10]:
                    addr = entry.get("address", "")
                    wallet_chains = entry.get("chains", ["ethereum"])
                    obs.extend(await self._observe_wallet(addr, wallet_chains))
                    obs.extend(await self._observe_approvals(addr, wallet_chains))
            except Exception:
                pass
        # Heartbeat with LOW priority -- won't trigger LLM on its own anymore
        obs.append({
            "source": "sentinel", "type": "heartbeat",
            "data": {"cycle": self._cycle_count, "chains": chains,
                     "message": "Sentinel active. All systems operational."},
            "priority": 2,  # Low priority -- won't force LLM call
        })
        return obs

    async def _observe_portfolio(self, address: str, chains: list[str]) -> list[dict]:
        """Full portfolio observation."""
        obs = []
        # Combine wallet + approval observations
        obs.extend(await self._observe_wallet(address, chains))
        obs.extend(await self._observe_approvals(address, chains))
        return obs

    async def _think_and_act(self, goals, observations, event, cycle_id: str) -> dict:
        """
        THINK+ACT phase: Feed ONLY ambiguous observations to LangGraph brain.
        Threats have already been auto-alerted. Safe observations are dropped.
        """
        if not self._agent_fn:
            return {"response": "No agent function configured"}

        goal_summary = ", ".join([
            "%s(%s on %s)" % (g.type.value, g.target[:10], ",".join(g.chains))
            for g in goals[:5]
        ])

        obs_text = json.dumps(observations[:10], indent=2, default=str)

        message = (
            "[AUTONOMOUS MODE — Cycle #%d]\n"
            "[Active Goals: %s]\n"
            "[Ambiguous Observations (%d items — these passed triage as needing your judgment)]\n%s\n\n"
            "These observations were NOT clear-cut threats or clear-cut safe. "
            "Your job is to reason about each one and decide:\n"
            "1. INVESTIGATE: Use tools if needed (scam_check, check_contract, scan_approvals)\n"
            "2. CLASSIFY: Is this actually a threat, false alarm, or needs more data?\n"
            "3. ALERT: Only flag things that are genuinely dangerous\n"
            "4. LOG: Record important findings to the GOAT chain\n"
            "Be precise. Don't cry wolf — you are a professional sentinel."
        ) % (self._cycle_count, goal_summary, len(observations), obs_text)

        try:
            result = await self._agent_fn(message, thread_id="autonomous_%s" % cycle_id)
            return result
        except Exception as e:
            print("[Perception] Think+Act error: %s" % e)
            return {"response": "Error: %s" % str(e)}

    async def _evaluate(self, goals, observations, cycle_id: str):
        """EVALUATE phase: Update goal statuses and store results in memory."""
        for goal in goals:
            relevant_obs = [o for o in observations
                            if goal.target == "*" or goal.target in str(o.get("data", {}))]
            result_summary = "%d observations, %d relevant" % (len(observations), len(relevant_obs))
            self._goals.update_goal_status(goal.id, result_summary)

        if self._memory:
            self._memory.remember(
                "perception_cycles", cycle_id,
                json.dumps({
                    "cycle": self._cycle_count,
                    "goals": len(goals),
                    "observations": len(observations),
                    "llm_calls_total": self._llm_calls_total,
                    "llm_calls_skipped": self._llm_calls_skipped,
                    "timestamp": time.time(),
                })
            )

    # ── TRIAGE (new) ─────────────────────────────────────────

    def _triage(self, observations: list[dict]) -> tuple[list, list, list]:
        """
        Split observations into 3 buckets:
          SAFE — auto-dismiss (heartbeats, verified protocol interactions, low priority)
          AMBIGUOUS — send to LLM (needs reasoning)
          THREAT — auto-alert without LLM (known scam, confirmed threat)
        """
        safe = []
        ambiguous = []
        threats = []

        for obs in observations:
            obs_type = obs.get("type", "")
            priority = obs.get("priority", 0)
            data = obs.get("data", {})

            # 1. Low priority → auto-dismiss
            if priority <= 3:
                safe.append(obs)
                continue

            # 2. Known high-threat types → auto-alert
            if obs_type in ("SCAM_INTERACTION", "KNOWN_SCAM_ADDRESS", "KNOWN_MALICIOUS"):
                threats.append(obs)
                continue

            # 3. Use rules engine on address interactions if available
            if self._rules and obs_type in ("recent_outflows", "risky_approvals"):
                target_addr = data.get("address", "")
                chain = data.get("chain", "ethereum")
                if target_addr:
                    from services.rules_engine import Trust
                    trust, _ = self._rules.classify(target_addr, chain)
                    if trust == Trust.TRUSTED:
                        safe.append(obs)
                        continue
                    elif trust == Trust.UNTRUSTED:
                        threats.append(obs)
                        continue

            # 4. Priority-based fallback
            if priority >= 8:
                ambiguous.append(obs)  # High priority but not definitive—ask LLM
            elif priority >= 5:
                ambiguous.append(obs)
            else:
                safe.append(obs)

        return safe, ambiguous, threats

    # ── DEDUP ─────────────────────────────────────────────────

    def _dedup_observations(self, observations: list[dict]) -> list[dict]:
        """
        Remove observations identical to ones we saw in the last cycle.
        Uses content hashing to detect duplicates.
        """
        fresh = []
        now = time.time()
        dedup_window = self._interval * 2  # Suppress if seen within 2 cycles

        for obs in observations:
            obs_hash = self._hash_observation(obs)
            last_seen = self._observation_hashes.get(obs_hash)

            if last_seen and (now - last_seen) < dedup_window:
                continue  # Skip duplicate

            self._observation_hashes[obs_hash] = now
            fresh.append(obs)

        # Cleanup old hashes (keep last 1000)
        if len(self._observation_hashes) > 1000:
            sorted_hashes = sorted(self._observation_hashes.items(), key=lambda x: x[1])
            self._observation_hashes = dict(sorted_hashes[-500:])

        return fresh

    def _hash_observation(self, obs: dict) -> str:
        """Create a stable hash for an observation (ignoring timestamps)."""
        stable = {
            "source": obs.get("source", ""),
            "type": obs.get("type", ""),
            "data_key": str(obs.get("data", {}).get("address", "")) +
                       str(obs.get("data", {}).get("chain", "")) +
                       str(obs.get("data", {}).get("count", "")),
        }
        return hashlib.md5(json.dumps(stable, sort_keys=True).encode()).hexdigest()

    # ── AUTO-ALERT (no LLM) ──────────────────────────────────

    async def _auto_alert(self, obs: dict):
        """Auto-alert for definitive threats. No LLM call needed."""
        data = obs.get("data", {})
        wallet = data.get("wallet", data.get("address", "unknown"))
        chain = data.get("chain", "ethereum")

        if self._alert_mgr:
            from services.alert_manager import AlertAction
            alert = self._alert_mgr.triage(
                wallet=wallet, chain=chain,
                alert_type=obs.get("type", "AUTO_THREAT"),
                severity="CRITICAL",
                detail=json.dumps(data, default=str)[:500],
                confidence=0.90,
            )
            if alert.decision.action in (AlertAction.ALERT_USER, AlertAction.BLOCK):
                print("[Perception] AUTO-ALERT: %s for %s" % (obs.get("type"), wallet))
                # Log to memory
                if self._memory:
                    self._memory.log_incident(wallet, obs.get("type", "threat"),
                                              json.dumps(data, default=str)[:300])
        else:
            # No alert manager — just print
            print("[Perception] THREAT DETECTED (no alert manager): %s" % obs.get("type"))
            if self._memory:
                self._memory.log_incident(wallet, obs.get("type", "threat"),
                                          json.dumps(data, default=str)[:300])

    def get_status(self) -> dict:
        """Get perception loop status."""
        return {
            "running": self._running,
            "cycleCount": self._cycle_count,
            "interval": self._interval,
            "lastResult": self._last_cycle_result,
            "pendingEvents": self._event_queue.qsize(),
            "mode": "autonomous" if self._running else "reactive",
            "llmCallsTotal": self._llm_calls_total,
            "llmCallsSkipped": self._llm_calls_skipped,
            "llmSavingsPercent": round(
                self._llm_calls_skipped / max(1, self._llm_calls_total + self._llm_calls_skipped) * 100, 1
            ),
        }
