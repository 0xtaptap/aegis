"""
Crypto Guardian — Goal Engine
Configurable goals that drive autonomous agent behavior.
Goals are persistent (SQLite) and feed into the perception loop.
"""

import os
import json
import time
import sqlite3
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class GoalType(str, Enum):
    PROTECT_WALLET = "protect_wallet"         # Monitor + defend a wallet
    MONITOR_APPROVALS = "monitor_approvals"   # Watch for risky approvals
    HUNT_SCAMS = "hunt_scams"                 # Proactively scan for scam contracts
    TRACK_THREATS = "track_threats"           # Follow threat intel patterns
    GUARD_PORTFOLIO = "guard_portfolio"       # Full portfolio risk management


@dataclass
class Goal:
    id: str
    type: GoalType
    target: str                     # wallet address, contract, or "*" for global
    chains: list[str] = field(default_factory=lambda: ["ethereum"])
    priority: int = 5              # 1=low, 10=critical
    active: bool = True
    description: str = ""
    created_at: float = field(default_factory=time.time)
    last_checked: float = 0.0
    check_count: int = 0
    last_result: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d


class GoalEngine:
    """Manages persistent agent goals in SQLite."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "data", "goals.db")
        self._db_path = db_path
        self._init_db()
        self._auto_seed()

    def _init_db(self):
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS goals (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                chains TEXT DEFAULT '["ethereum"]',
                priority INTEGER DEFAULT 5,
                active INTEGER DEFAULT 1,
                description TEXT DEFAULT '',
                created_at REAL,
                last_checked REAL DEFAULT 0,
                check_count INTEGER DEFAULT 0,
                last_result TEXT DEFAULT ''
            )
        """)
        conn.commit()
        conn.close()
        print("[GoalEngine] Initialized (%s)" % self._db_path)

    def _auto_seed(self):
        """Seed default goals on first boot so the agent always has a mission."""
        stats = self.get_stats()
        if stats["total"] > 0:
            return  # Already has goals
        # Seed 3 default goals
        self.add_goal("hunt_scams", "*",
                      chains=["ethereum", "polygon", "bsc", "arbitrum", "base"],
                      priority=8,
                      description="Proactively scan for new scam contracts and patterns across all chains")
        self.add_goal("track_threats", "*",
                      chains=["ethereum", "polygon", "bsc"],
                      priority=7,
                      description="Monitor threat intelligence feeds and community scam reports")
        self.add_goal("monitor_approvals", "*",
                      chains=["ethereum", "polygon", "bsc", "arbitrum", "base"],
                      priority=6,
                      description="Watch all connected wallets for risky approvals")
        print("[GoalEngine] Auto-seeded 3 default goals")

    def add_goal(self, goal_type: str, target: str, chains: list[str] = None,
                 priority: int = 5, description: str = "") -> Goal:
        """Add a new goal."""
        goal_id = "goal_%s_%d" % (goal_type[:8], int(time.time() * 1000) % 100000)
        goal = Goal(
            id=goal_id,
            type=GoalType(goal_type),
            target=target.lower() if target != "*" else "*",
            chains=chains or ["ethereum"],
            priority=priority,
            description=description or "Auto-generated %s goal for %s" % (goal_type, target[:10]),
        )
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            "INSERT OR REPLACE INTO goals (id, type, target, chains, priority, active, description, created_at, last_checked, check_count, last_result) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (goal.id, goal.type.value, goal.target, json.dumps(goal.chains),
             goal.priority, int(goal.active), goal.description,
             goal.created_at, goal.last_checked, goal.check_count, goal.last_result)
        )
        conn.commit()
        conn.close()
        print("[GoalEngine] Added goal: %s → %s (%s)" % (goal.type.value, goal.target[:10], goal.id))
        return goal

    def remove_goal(self, goal_id: str) -> bool:
        """Remove a goal by ID."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.execute("DELETE FROM goals WHERE id = ?", (goal_id,))
        conn.commit()
        conn.close()
        return cursor.rowcount > 0

    def get_active_goals(self) -> list[Goal]:
        """Get all active goals, sorted by priority (highest first)."""
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT id, type, target, chains, priority, active, description, "
            "created_at, last_checked, check_count, last_result "
            "FROM goals WHERE active = 1 ORDER BY priority DESC"
        ).fetchall()
        conn.close()
        return [self._row_to_goal(r) for r in rows]

    def list_goals(self) -> list[dict]:
        """List all goals as dicts."""
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT id, type, target, chains, priority, active, description, "
            "created_at, last_checked, check_count, last_result FROM goals ORDER BY priority DESC"
        ).fetchall()
        conn.close()
        return [self._row_to_goal(r).to_dict() for r in rows]

    def update_goal_status(self, goal_id: str, last_result: str = ""):
        """Mark a goal as checked."""
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            "UPDATE goals SET last_checked = ?, check_count = check_count + 1, last_result = ? WHERE id = ?",
            (time.time(), last_result[:500], goal_id)
        )
        conn.commit()
        conn.close()

    def get_stats(self) -> dict:
        """Get goal engine statistics."""
        conn = sqlite3.connect(self._db_path)
        total = conn.execute("SELECT COUNT(*) FROM goals").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM goals WHERE active = 1").fetchone()[0]
        conn.close()
        return {"total": total, "active": active}

    def _row_to_goal(self, row) -> Goal:
        return Goal(
            id=row[0], type=GoalType(row[1]), target=row[2],
            chains=json.loads(row[3]), priority=row[4], active=bool(row[5]),
            description=row[6], created_at=row[7], last_checked=row[8],
            check_count=row[9], last_result=row[10],
        )
