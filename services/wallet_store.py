"""
Crypto Guardian - Multi-Wallet Store
SQLite-backed storage for tracking multiple wallets per user.
"""

import os
import sqlite3
import time
import asyncio
import json


class WalletStore:
    """Store and manage multiple wallets with SQLite persistence."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "data", "wallets.db")
        self._db_path = db_path
        self._init_db()

    def _init_db(self):
        """Create wallets table."""
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wallets (
                    address TEXT PRIMARY KEY,
                    label TEXT DEFAULT '',
                    chains TEXT DEFAULT '["ethereum"]',
                    added_at REAL,
                    last_scanned REAL DEFAULT 0
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print("[WalletStore] DB init error: %s" % e)

    def add_wallet(self, address, label="", chains=None):
        """Add a wallet to track."""
        addr = address.lower()
        chain_list = chains or ["ethereum", "polygon", "bsc", "arbitrum", "base", "optimism", "avalanche"]
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT OR REPLACE INTO wallets (address, label, chains, added_at) VALUES (?, ?, ?, ?)",
                (addr, label, json.dumps(chain_list), time.time())
            )
            conn.commit()
            conn.close()
            return {"added": True, "address": addr, "label": label, "chains": chain_list}
        except Exception as e:
            return {"added": False, "error": str(e)}

    def remove_wallet(self, address):
        """Remove a wallet from tracking."""
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("DELETE FROM wallets WHERE address = ?", (address.lower(),))
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def list_wallets(self):
        """List all tracked wallets."""
        try:
            conn = sqlite3.connect(self._db_path)
            rows = conn.execute("SELECT address, label, chains, added_at, last_scanned FROM wallets").fetchall()
            conn.close()
            return [
                {
                    "address": row[0],
                    "label": row[1],
                    "chains": json.loads(row[2]),
                    "addedAt": row[3],
                    "lastScanned": row[4],
                }
                for row in rows
            ]
        except Exception:
            return []

    async def scan_all(self, blockchain_service, threat_intel=None):
        """Scan all tracked wallets across their chains. Returns aggregate risk view."""
        wallets = self.list_wallets()
        if not wallets:
            return {"wallets": 0, "totalApprovals": 0, "riskyApprovals": 0, "results": []}

        total_approvals = 0
        risky_approvals = 0
        results = []

        for wallet in wallets:
            addr = wallet["address"]
            wallet_result = {
                "address": addr,
                "label": wallet["label"],
                "chains": {},
            }

            # Scan each chain in parallel
            scan_tasks = []
            for chain in wallet["chains"]:
                scan_tasks.append(self._scan_wallet_chain(blockchain_service, addr, chain))

            chain_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            for i, chain in enumerate(wallet["chains"]):
                chain_data = chain_results[i]
                if isinstance(chain_data, Exception):
                    wallet_result["chains"][chain] = {"error": str(chain_data)}
                    continue

                wallet_result["chains"][chain] = chain_data
                total_approvals += chain_data.get("totalApprovals", 0)
                risky_approvals += chain_data.get("riskyApprovals", 0)

            results.append(wallet_result)

            # Update last_scanned
            try:
                conn = sqlite3.connect(self._db_path)
                conn.execute(
                    "UPDATE wallets SET last_scanned = ? WHERE address = ?",
                    (time.time(), addr)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

        return {
            "wallets": len(wallets),
            "totalApprovals": total_approvals,
            "riskyApprovals": risky_approvals,
            "results": results,
        }

    async def _scan_wallet_chain(self, blockchain_service, address, chain):
        """Scan a single wallet on a single chain."""
        try:
            approvals = await blockchain_service.get_approvals(address, chain)
            total = len(approvals) if isinstance(approvals, list) else 0
            risky = 0
            for a in (approvals if isinstance(approvals, list) else []):
                allowance = a.get("allowance", "0")
                if allowance and allowance != "0":
                    try:
                        val = int(allowance, 16) if isinstance(allowance, str) and allowance.startswith("0x") else int(allowance)
                        if val > 10**30:  # Unlimited approval
                            risky += 1
                    except (ValueError, TypeError):
                        pass
            return {"totalApprovals": total, "riskyApprovals": risky}
        except Exception as e:
            return {"totalApprovals": 0, "riskyApprovals": 0, "error": str(e)}


# Global singleton
wallet_store = WalletStore()
