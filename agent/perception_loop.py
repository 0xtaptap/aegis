"""
Crypto Guardian — Perception Loop
The autonomous brain: continuously observes blockchain → reasons → acts → evaluates.
This is what transforms the agent from a reactive chatbot to a goal-driven autonomous agent.
"""

import os
import json
import time
import asyncio
from typing import Optional


class PerceptionLoop:
    """
    Continuous observe → think → act → evaluate loop.
    Runs as a background asyncio task, driven by GoalEngine goals.
    Only triggers LLM reasoning when observations are non-trivial (saves API costs).
    """

    def __init__(self, goal_engine, blockchain_service, threat_intel, memory_store,
                 monitor=None, interval: int = 120):
        self._goals = goal_engine
        self._bc = blockchain_service
        self._threat = threat_intel
        self._memory = memory_store
        self._monitor = monitor
        self._interval = interval
        self._running = False
        self._task = None
        self._agent_fn = None          # set by set_agent_fn()
        self._event_queue = asyncio.Queue()  # for event-driven triggers
        self._cycle_count = 0
        self._last_cycle_result = ""

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
        """Main autonomous loop — ALWAYS runs, never skips."""
        # Wait a bit on startup for services to initialize
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

                # Get active goals
                goals = self._goals.get_active_goals()

                self._cycle_count += 1
                cycle_id = "cycle_%d_%d" % (self._cycle_count, int(time.time()))
                print("[Perception] ── Cycle #%d starting (%d goals, event=%s) ──" %
                      (self._cycle_count, len(goals), bool(event)))

                # ── OBSERVE ──
                observations = await self._observe(goals, event)

                # Also observe watchlist wallets from monitor (for wildcard goals)
                if self._monitor:
                    try:
                        watchlist = self._monitor.get_watchlist()
                        if watchlist:
                            for entry in watchlist[:5]:
                                addr = entry.get("address", "")
                                chains = entry.get("chains", ["ethereum"])
                                obs = await self._observe_wallet(addr, chains)
                                observations.extend(obs)
                        # Also pull recent alerts from monitor
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

                print("[Perception] Observed %d items" % len(observations))

                # ── THINK + ACT ──
                # Only call LLM if there are meaningful observations (saves API cost)
                if observations and self._agent_fn:
                    important = [o for o in observations if o.get("priority", 0) >= 5]
                    if important or event:
                        print("[Perception] Thinking... (%d important observations)" % len(important))
                        result = await self._think_and_act(goals, observations, event, cycle_id)
                        self._last_cycle_result = result.get("response", "")[:200]
                        print("[Perception] Action taken: %s" % self._last_cycle_result[:100])
                    else:
                        print("[Perception] Low-priority observations only — skipping LLM call")
                        self._last_cycle_result = "Cycle #%d: %d low-priority observations, no action needed" % (
                            self._cycle_count, len(observations))
                else:
                    self._last_cycle_result = "Cycle #%d: no observations" % self._cycle_count

                # ── EVALUATE ──
                await self._evaluate(goals, observations, cycle_id)

                print("[Perception] ── Cycle #%d complete ──" % self._cycle_count)

            except Exception as e:
                print("[Perception] Loop error: %s" % e)
                import traceback
                traceback.print_exc()

            # Sleep unless there are pending events
            if self._event_queue.empty():
                await asyncio.sleep(self._interval)
            else:
                await asyncio.sleep(5)  # Quick retry for queued events

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
        # 1. Check scam database
        obs.extend(await self._observe_scam_activity(chains))
        # 2. Check threat history
        obs.extend(await self._observe_threats())
        # 3. Check all watched wallets from monitor
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
        # 4. Always report a heartbeat so the LLM thinks even when quiet
        obs.append({
            "source": "sentinel", "type": "heartbeat",
            "data": {"cycle": self._cycle_count, "chains": chains,
                     "message": "Sentinel active. Review all observations and think about potential threats."},
            "priority": 8,
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
        THINK+ACT phase: Feed observations to LangGraph brain.
        The brain reasons about what to do and calls tools.
        """
        if not self._agent_fn:
            return {"response": "No agent function configured"}

        # Build context message for the LLM
        goal_summary = ", ".join([
            "%s(%s on %s)" % (g.type.value, g.target[:10], ",".join(g.chains))
            for g in goals[:5]
        ])

        # Filter to priority observations (save tokens)
        important = [o for o in observations if o.get("priority", 0) >= 5]
        if not important:
            important = observations[:3]

        obs_text = json.dumps(important[:10], indent=2, default=str)

        # Build autonomous reasoning prompt
        message = (
            "[AUTONOMOUS MODE — Cycle #%d]\n"
            "[Active Goals: %s]\n"
            "[Observations (%d total, %d important)]\n%s\n\n"
            "You are an always-on security sentinel. Based on these observations:\n"
            "1. ANALYZE: What threats, risks, or anomalies do you see?\n"
            "2. DETECT: Are there any scam patterns, risky approvals, or suspicious interactions?\n"
            "3. ACT: If threats found → use your tools to investigate deeper (scam_check, check_contract, scan_approvals)\n"
            "4. ALERT: Flag anything dangerous for the user\n"
            "5. LOG: Record important findings to the GOAT chain\n"
            "Think carefully. Even if things look quiet, consider what COULD be a threat.\n"
            "Be concise but thorough."
        ) % (self._cycle_count, goal_summary, len(observations), len(important), obs_text)

        try:
            result = await self._agent_fn(message, thread_id="autonomous_%s" % cycle_id)
            return result
        except Exception as e:
            print("[Perception] Think+Act error: %s" % e)
            return {"response": "Error: %s" % str(e)}

    async def _evaluate(self, goals, observations, cycle_id: str):
        """
        EVALUATE phase: Update goal statuses and store results in memory.
        """
        for goal in goals:
            # Update goal's last_checked timestamp
            relevant_obs = [o for o in observations
                            if goal.target == "*" or goal.target in str(o.get("data", {}))]
            result_summary = "%d observations, %d relevant" % (len(observations), len(relevant_obs))
            self._goals.update_goal_status(goal.id, result_summary)

        # Store cycle in memory
        if self._memory:
            self._memory.remember(
                "perception_cycles", cycle_id,
                json.dumps({
                    "cycle": self._cycle_count,
                    "goals": len(goals),
                    "observations": len(observations),
                    "timestamp": time.time(),
                })
            )

    def get_status(self) -> dict:
        """Get perception loop status."""
        return {
            "running": self._running,
            "cycleCount": self._cycle_count,
            "interval": self._interval,
            "lastResult": self._last_cycle_result,
            "pendingEvents": self._event_queue.qsize(),
            "mode": "autonomous" if self._running else "reactive",
        }
