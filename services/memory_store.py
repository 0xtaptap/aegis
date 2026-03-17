"""
Crypto Guardian — Persistent Memory Store
Long-term agent memory that survives restarts.
Stores wallet profiles, incidents, conversation summaries, and threat history.
"""

import os
import json
import time
import sqlite3
from typing import Optional


class MemoryStore:
    """
    SQLite-backed persistent memory for the autonomous agent.
    Categories: wallet_profiles, incidents, conversations, threats, perception_cycles, facts.
    """

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "data", "memory.db")
        self._db_path = db_path
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                timestamp REAL NOT NULL,
                UNIQUE(category, key)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                severity TEXT DEFAULT 'MEDIUM',
                details TEXT NOT NULL,
                chain TEXT DEFAULT 'ethereum',
                resolved INTEGER DEFAULT 0,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wallet_profiles (
                address TEXT PRIMARY KEY,
                first_seen REAL,
                last_scanned REAL,
                risk_score INTEGER DEFAULT 0,
                total_scans INTEGER DEFAULT 0,
                notes TEXT DEFAULT '{}',
                chains TEXT DEFAULT '["ethereum"]'
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_cat ON memory(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_addr ON incidents(address)")
        conn.commit()
        conn.close()
        print("[Memory] Persistent memory initialized (%s)" % self._db_path)

    # ── General Memory ─────────────────────────────────────────
    def remember(self, category: str, key: str, value: str):
        """Store a fact. If key exists in category, it gets updated."""
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            "INSERT OR REPLACE INTO memory (category, key, value, timestamp) VALUES (?, ?, ?, ?)",
            (category, key, value, time.time())
        )
        conn.commit()
        conn.close()

    def recall(self, category: str, key: str) -> Optional[str]:
        """Retrieve a stored fact."""
        conn = sqlite3.connect(self._db_path)
        row = conn.execute(
            "SELECT value FROM memory WHERE category = ? AND key = ?", (category, key)
        ).fetchone()
        conn.close()
        return row[0] if row else None

    def recall_category(self, category: str, limit: int = 20) -> list[dict]:
        """Get all entries in a category."""
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT key, value, timestamp FROM memory WHERE category = ? ORDER BY timestamp DESC LIMIT ?",
            (category, limit)
        ).fetchall()
        conn.close()
        return [{"key": r[0], "value": r[1], "timestamp": r[2]} for r in rows]

    def forget(self, category: str, key: str) -> bool:
        """Remove a specific memory."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.execute("DELETE FROM memory WHERE category = ? AND key = ?", (category, key))
        conn.commit()
        conn.close()
        return cursor.rowcount > 0

    # ── Wallet Profiles ────────────────────────────────────────
    def update_wallet_profile(self, address: str, risk_score: int = 0,
                               chains: list[str] = None, notes: dict = None):
        """Create or update a wallet profile."""
        addr = address.lower()
        conn = sqlite3.connect(self._db_path)
        existing = conn.execute("SELECT address FROM wallet_profiles WHERE address = ?", (addr,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE wallet_profiles SET last_scanned = ?, risk_score = ?, "
                "total_scans = total_scans + 1, notes = ?, chains = ? WHERE address = ?",
                (time.time(), risk_score, json.dumps(notes or {}),
                 json.dumps(chains or ["ethereum"]), addr)
            )
        else:
            conn.execute(
                "INSERT INTO wallet_profiles (address, first_seen, last_scanned, risk_score, total_scans, notes, chains) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)",
                (addr, time.time(), time.time(), risk_score,
                 json.dumps(notes or {}), json.dumps(chains or ["ethereum"]))
            )
        conn.commit()
        conn.close()

    def get_wallet_profile(self, address: str) -> Optional[dict]:
        """Get full wallet profile."""
        addr = address.lower()
        conn = sqlite3.connect(self._db_path)
        row = conn.execute(
            "SELECT address, first_seen, last_scanned, risk_score, total_scans, notes, chains "
            "FROM wallet_profiles WHERE address = ?", (addr,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "address": row[0], "firstSeen": row[1], "lastScanned": row[2],
            "riskScore": row[3], "totalScans": row[4],
            "notes": json.loads(row[5]), "chains": json.loads(row[6]),
        }

    # ── Incidents ──────────────────────────────────────────────
    def log_incident(self, address: str, incident_type: str, details: str,
                     severity: str = "MEDIUM", chain: str = "ethereum"):
        """Record a security incident."""
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            "INSERT INTO incidents (address, incident_type, severity, details, chain, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (address.lower(), incident_type, severity, details, chain, time.time())
        )
        conn.commit()
        conn.close()

    def get_incidents(self, address: str = None, limit: int = 20) -> list[dict]:
        """Get incidents, optionally filtered by address."""
        conn = sqlite3.connect(self._db_path)
        if address:
            rows = conn.execute(
                "SELECT id, address, incident_type, severity, details, chain, resolved, timestamp "
                "FROM incidents WHERE address = ? ORDER BY timestamp DESC LIMIT ?",
                (address.lower(), limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, address, incident_type, severity, details, chain, resolved, timestamp "
                "FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        conn.close()
        return [{
            "id": r[0], "address": r[1], "type": r[2], "severity": r[3],
            "details": r[4], "chain": r[5], "resolved": bool(r[6]), "timestamp": r[7],
        } for r in rows]

    # ── Context for LLM ───────────────────────────────────────
    def get_context_for_wallet(self, address: str) -> str:
        """Build memory context string for injecting into LLM prompts."""
        profile = self.get_wallet_profile(address)
        incidents = self.get_incidents(address, limit=5)

        parts = []
        if profile:
            parts.append(
                "[Memory] Wallet %s — Risk: %d/100, Scanned %d times, First seen: %s" %
                (address[:10], profile["riskScore"], profile["totalScans"],
                 time.strftime("%Y-%m-%d", time.localtime(profile["firstSeen"])))
            )
        if incidents:
            parts.append("[Memory] %d past incidents:" % len(incidents))
            for inc in incidents[:3]:
                parts.append("  - %s: %s (%s)" % (inc["type"], inc["details"][:80], inc["severity"]))

        return "\n".join(parts) if parts else ""

    def get_context_for_goal(self, goal_target: str) -> str:
        """Build memory context relevant to a specific goal target."""
        if goal_target == "*":
            # Global context — recent incidents
            incidents = self.get_incidents(limit=5)
            if incidents:
                parts = ["[Memory] Recent incidents across all wallets:"]
                for inc in incidents[:3]:
                    parts.append("  - %s on %s: %s" % (inc["type"], inc["address"][:10], inc["details"][:60]))
                return "\n".join(parts)
            return ""
        return self.get_context_for_wallet(goal_target)

    # ── Stats ─────────────────────────────────────────────────
    def get_stats(self) -> dict:
        conn = sqlite3.connect(self._db_path)
        memories = conn.execute("SELECT COUNT(*) FROM memory").fetchone()[0]
        profiles = conn.execute("SELECT COUNT(*) FROM wallet_profiles").fetchone()[0]
        incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        conn.close()
        return {"memories": memories, "walletProfiles": profiles, "incidents": incidents}
