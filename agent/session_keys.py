"""
Crypto Guardian - Session Key Manager (GOAT + Safe Pattern)
Now with SQLite persistence (no more Python dict).

Manages per-user session key configurations for Safe smart account execution.
Default mode: READ_ONLY - blocks all on-chain execution.
"""

import os
import time
import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SessionMode(str, Enum):
    READ_ONLY = "READ_ONLY"        # Scan/simulate only
    LIMITED = "LIMITED"              # Execute within caps
    FULL = "FULL"                   # Full execution (NOT recommended)


@dataclass
class SessionKey:
    """A session key with spending limits and protocol restrictions."""
    session_id: str
    wallet_address: str
    mode: SessionMode = SessionMode.READ_ONLY
    max_spend_usd: float = 0.0
    allowed_protocols: list = field(default_factory=list)
    allowed_chains: list = field(default_factory=lambda: ["ethereum"])
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    total_spent_usd: float = 0.0
    action_log: list = field(default_factory=list)

    @property
    def is_expired(self):
        return self.expires_at > 0 and time.time() > self.expires_at

    @property
    def remaining_budget(self):
        return max(0.0, self.max_spend_usd - self.total_spent_usd)

    def to_dict(self):
        return {
            "sessionId": self.session_id,
            "wallet": self.wallet_address,
            "mode": self.mode.value,
            "maxSpendUsd": self.max_spend_usd,
            "remainingBudget": self.remaining_budget,
            "allowedProtocols": self.allowed_protocols,
            "allowedChains": self.allowed_chains,
            "expired": self.is_expired,
            "actionsLogged": len(self.action_log),
        }


class SessionKeyManager:
    """
    Manages session keys per wallet with SQLite persistence.
    Falls back to in-memory if SQLite fails.
    """

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "data", "sessions.db")
        self._db_path = db_path
        self._memory = {}  # In-memory fallback
        self._init_db()

    def _init_db(self):
        """Create the sessions table if it does not exist."""
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    wallet TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    mode TEXT DEFAULT 'READ_ONLY',
                    max_spend_usd REAL DEFAULT 0.0,
                    total_spent_usd REAL DEFAULT 0.0,
                    allowed_protocols TEXT DEFAULT '[]',
                    allowed_chains TEXT DEFAULT '["ethereum"]',
                    created_at REAL,
                    expires_at REAL DEFAULT 0.0,
                    action_log TEXT DEFAULT '[]'
                )
            """)
            conn.commit()
            conn.close()
            self._use_db = True
        except Exception as e:
            print("[Sessions] SQLite init failed, using in-memory: %s" % e)
            self._use_db = False

    def _save_to_db(self, sk):
        """Persist a session key to SQLite."""
        if not self._use_db:
            return
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                INSERT OR REPLACE INTO sessions
                (wallet, session_id, mode, max_spend_usd, total_spent_usd,
                 allowed_protocols, allowed_chains, created_at, expires_at, action_log)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sk.wallet_address,
                sk.session_id,
                sk.mode.value,
                sk.max_spend_usd,
                sk.total_spent_usd,
                json.dumps(sk.allowed_protocols),
                json.dumps(sk.allowed_chains),
                sk.created_at,
                sk.expires_at,
                json.dumps(sk.action_log[-50:]),  # Keep last 50 actions
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print("[Sessions] DB save error: %s" % e)

    def _load_from_db(self, wallet):
        """Load a session key from SQLite."""
        if not self._use_db:
            return None
        try:
            conn = sqlite3.connect(self._db_path)
            row = conn.execute(
                "SELECT * FROM sessions WHERE wallet = ?", (wallet,)
            ).fetchone()
            conn.close()
            if not row:
                return None
            return SessionKey(
                session_id=row[1],
                wallet_address=row[0],
                mode=SessionMode(row[2]),
                max_spend_usd=row[3],
                total_spent_usd=row[4],
                allowed_protocols=json.loads(row[5]),
                allowed_chains=json.loads(row[6]),
                created_at=row[7],
                expires_at=row[8],
                action_log=json.loads(row[9]),
            )
        except Exception as e:
            print("[Sessions] DB load error: %s" % e)
            return None

    def create_session(
        self,
        wallet_address,
        mode="READ_ONLY",
        max_spend_usd=0.0,
        allowed_protocols=None,
        allowed_chains=None,
        ttl_seconds=3600,
    ):
        """Create a new session key for a wallet."""
        session_id = hashlib.sha256(
            ("%s:%s" % (wallet_address, time.time())).encode()
        ).hexdigest()[:16]

        session_mode = SessionMode(mode) if mode in SessionMode.__members__ else SessionMode.READ_ONLY

        sk = SessionKey(
            session_id=session_id,
            wallet_address=wallet_address.lower(),
            mode=session_mode,
            max_spend_usd=max_spend_usd if session_mode != SessionMode.READ_ONLY else 0.0,
            allowed_protocols=allowed_protocols or [],
            allowed_chains=allowed_chains or ["ethereum"],
            expires_at=time.time() + ttl_seconds if ttl_seconds > 0 else 0.0,
        )
        self._memory[wallet_address.lower()] = sk
        self._save_to_db(sk)
        return sk

    def get_session(self, wallet_address):
        """Get the active session for a wallet (memory first, then DB)."""
        addr = wallet_address.lower()
        sk = self._memory.get(addr)
        if not sk:
            sk = self._load_from_db(addr)
            if sk:
                self._memory[addr] = sk
        if sk and sk.is_expired:
            return None
        return sk

    def get_or_create_readonly(self, wallet_address):
        """Get existing session or create a default READ_ONLY one."""
        sk = self.get_session(wallet_address)
        if not sk:
            sk = self.create_session(wallet_address, mode="READ_ONLY")
        return sk

    def validate_action(
        self, wallet_address, action_type, estimated_cost_usd=0.0,
        protocol="", chain="ethereum",
    ):
        """Validate whether an action is allowed under the current session."""
        sk = self.get_session(wallet_address)

        if not sk:
            return {"allowed": False, "reason": "No active session.", "session": None}

        if sk.is_expired:
            return {"allowed": False, "reason": "Session expired.", "session": sk.to_dict()}

        # READ_ONLY: only scans and simulations
        if sk.mode == SessionMode.READ_ONLY:
            read_only_actions = {"scan", "simulate", "check_phishing", "risk_score", "monitor", "status"}
            if action_type not in read_only_actions:
                return {
                    "allowed": False,
                    "reason": "READ-ONLY mode. Upgrade session to LIMITED to execute '%s'." % action_type,
                    "session": sk.to_dict(),
                }
            return {"allowed": True, "reason": "Read-only permitted.", "session": sk.to_dict()}

        # LIMITED: check limits
        if sk.mode == SessionMode.LIMITED:
            if estimated_cost_usd > sk.remaining_budget:
                return {
                    "allowed": False,
                    "reason": "Cost $%.2f exceeds remaining budget $%.2f." % (estimated_cost_usd, sk.remaining_budget),
                    "session": sk.to_dict(),
                }
            if protocol and sk.allowed_protocols and protocol.lower() not in [p.lower() for p in sk.allowed_protocols]:
                return {
                    "allowed": False,
                    "reason": "Protocol '%s' not in allowed list." % protocol,
                    "session": sk.to_dict(),
                }
            if chain not in sk.allowed_chains:
                return {
                    "allowed": False,
                    "reason": "Chain '%s' not in allowed chains." % chain,
                    "session": sk.to_dict(),
                }

        return {"allowed": True, "reason": "Action within limits.", "session": sk.to_dict()}

    def log_action(self, wallet_address, action):
        """Log an executed action and deduct from budget."""
        sk = self.get_session(wallet_address)
        if sk:
            sk.action_log.append({**action, "timestamp": time.time()})
            if "cost_usd" in action:
                sk.total_spent_usd += action["cost_usd"]
            self._save_to_db(sk)

    def revoke_session(self, wallet_address):
        """Revoke a session key."""
        addr = wallet_address.lower()
        if addr in self._memory:
            del self._memory[addr]
        if self._use_db:
            try:
                conn = sqlite3.connect(self._db_path)
                conn.execute("DELETE FROM sessions WHERE wallet = ?", (addr,))
                conn.commit()
                conn.close()
            except Exception:
                pass
        return True


# Global singleton
session_manager = SessionKeyManager()
