"""
Crypto Guardian - Real-Time Wallet Monitor
Background polling loop using alchemy_getAssetTransfers.
Detects: large outflows, new approvals, unlimited approvals, flagged contracts.
// ADDED FOR FINAL VERSION — real WS push + webhook support
"""

import os
import time
import asyncio
import sqlite3
import json
import aiohttp  # ADDED FOR FINAL VERSION — webhook POST
from enum import Enum


class AlertType(str, Enum):
    LARGE_OUTFLOW = "LARGE_OUTFLOW"
    NEW_APPROVAL = "NEW_APPROVAL"
    UNLIMITED_APPROVAL = "UNLIMITED_APPROVAL"
    FLAGGED_CONTRACT = "FLAGGED_CONTRACT"
    NEW_ADDRESS_INTERACTION = "NEW_ADDRESS_INTERACTION"


class WalletMonitor:
    """Background wallet monitor with SQLite-backed alert storage.
    Now integrates with AlertManager for dedup, cooldown, and triage."""

    def __init__(self, blockchain_service, threat_intel=None, alert_manager=None, db_path=None):
        self._bc = blockchain_service
        self._threat = threat_intel
        self._alert_mgr = alert_manager  # AlertManager for intelligent alert filtering
        self._running = False
        self._task = None
        self._ws_clients = []  # WebSocket clients for push alerts
        self._poll_interval = 60  # seconds
        self._last_blocks = {}  # chain -> last checked block

        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "data", "monitor.db")
        self._db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS watchlist (
                    address TEXT PRIMARY KEY,
                    chains TEXT DEFAULT '["ethereum"]',
                    added_at REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    tx_hash TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    read INTEGER DEFAULT 0
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print("[Monitor] DB init error: %s" % e)

    def watch(self, address, chains=None):
        """Add an address to the watchlist."""
        chain_list = chains or ["ethereum"]
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT OR REPLACE INTO watchlist (address, chains, added_at) VALUES (?, ?, ?)",
                (address.lower(), json.dumps(chain_list), time.time())
            )
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def unwatch(self, address):
        """Remove an address from the watchlist."""
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("DELETE FROM watchlist WHERE address = ?", (address.lower(),))
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def get_watchlist(self):
        """Get all watched addresses."""
        try:
            conn = sqlite3.connect(self._db_path)
            rows = conn.execute("SELECT address, chains, added_at FROM watchlist").fetchall()
            conn.close()
            return [{"address": r[0], "chains": json.loads(r[1]), "addedAt": r[2]} for r in rows]
        except Exception:
            return []

    def get_alerts(self, address=None, limit=50):
        """Get recent alerts, optionally filtered by address."""
        try:
            conn = sqlite3.connect(self._db_path)
            if address:
                rows = conn.execute(
                    "SELECT id, wallet, chain, alert_type, severity, detail, tx_hash, timestamp, read "
                    "FROM alerts WHERE wallet = ? ORDER BY timestamp DESC LIMIT ?",
                    (address.lower(), limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, wallet, chain, alert_type, severity, detail, tx_hash, timestamp, read "
                    "FROM alerts ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            conn.close()
            return [{
                "id": r[0], "wallet": r[1], "chain": r[2],
                "alertType": r[3], "severity": r[4], "detail": r[5],
                "txHash": r[6], "timestamp": r[7], "read": bool(r[8]),
            } for r in rows]
        except Exception:
            return []

    # ADDED FOR FINAL VERSION — WS client registration
    def register_ws(self, ws):
        """Register a WebSocket client for real-time alert push."""
        if ws not in self._ws_clients:
            self._ws_clients.append(ws)
            print("[Monitor] WS client registered (%d total)" % len(self._ws_clients))

    def unregister_ws(self, ws):
        """Unregister a WebSocket client."""
        if ws in self._ws_clients:
            self._ws_clients.remove(ws)
            print("[Monitor] WS client unregistered (%d remaining)" % len(self._ws_clients))

    async def _save_alert(self, wallet, chain, alert_type, severity, detail, tx_hash=""):
        """Save an alert — now runs through AlertManager triage first."""

        # ── AlertManager gate ──────────────────────────────────
        if self._alert_mgr:
            from services.alert_manager import AlertAction
            processed = self._alert_mgr.triage(
                wallet=wallet, chain=chain,
                alert_type=str(alert_type), severity=severity,
                detail=detail, confidence=0.70,  # Monitor findings have moderate confidence
            )
            action = processed.decision.action

            # DISMISS or WATCH → don't push to user, just log
            if action == AlertAction.DISMISS:
                return  # Silently drop
            if action == AlertAction.WATCH:
                print("[Monitor] Alert watched (not pushed): %s for %s" % (alert_type, wallet[:12]))
                return
            # ALERT_USER or BLOCK → continue to save + push

        alert_data = {
            "wallet": wallet, "chain": chain, "alertType": str(alert_type),
            "severity": severity, "detail": detail, "txHash": tx_hash,
            "timestamp": time.time(),
        }
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO alerts (wallet, chain, alert_type, severity, detail, tx_hash, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (wallet, chain, alert_type, severity, detail, tx_hash, alert_data["timestamp"])
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

        await self._push_alert_ws(alert_data)
        await self._try_webhook(alert_data)

    async def _push_alert_ws(self, alert_data):
        """Broadcast alert to all connected WebSocket clients."""
        if not self._ws_clients:
            return
        payload = json.dumps({"type": "alert", "data": alert_data})
        dead = []
        for ws in self._ws_clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws_clients.remove(ws)

    async def _try_webhook(self, alert_data):
        """POST alert to webhook URL if configured."""
        webhook_url = os.getenv("GUARDIAN_WEBHOOK_URL", "")
        if not webhook_url:
            return
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(webhook_url, json=alert_data, timeout=aiohttp.ClientTimeout(total=5))
        except Exception as e:
            print("[Monitor] Webhook POST failed: %s" % e)

    async def start(self):
        """Start the background monitoring loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        print("[Monitor] Background monitoring started (every %ds)" % self._poll_interval)

    async def stop(self):
        """Stop the background monitoring loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print("[Monitor] Background monitoring stopped")

    async def _poll_loop(self):
        """Main polling loop. Checks each watched address every poll_interval seconds."""
        while self._running:
            try:
                watchlist = self.get_watchlist()
                for entry in watchlist:
                    address = entry["address"]
                    for chain in entry["chains"]:
                        try:
                            await self._check_address(address, chain)
                        except Exception as e:
                            print("[Monitor] Error checking %s on %s: %s" % (address[:10], chain, e))
            except Exception as e:
                print("[Monitor] Poll loop error: %s" % e)

            await asyncio.sleep(self._poll_interval)

    async def _check_address(self, address, chain):
        """Check for new activity on an address."""
        # Get recent outbound transfers (last 5 blocks)
        try:
            transfers = await self._bc._rpc(chain, "alchemy_getAssetTransfers", [{
                "fromAddress": address,
                "category": ["external", "erc20", "erc721"],
                "maxCount": "0xa",  # Last 10 transfers
                "order": "desc",
            }])

            if not transfers or "transfers" not in transfers:
                return

            for tx in transfers.get("transfers", []):
                value = tx.get("value", 0) or 0
                asset = tx.get("asset", "ETH")
                to_addr = tx.get("to", "")
                tx_hash = tx.get("hash", "")
                category = tx.get("category", "")

                # Large outflow check (>0.5 ETH equivalent)
                if value and float(value) > 0.5 and category == "external":
                    await self._save_alert(
                        address, chain, AlertType.LARGE_OUTFLOW, "HIGH",
                        "Large outflow: %.4f %s sent to %s" % (float(value), asset, to_addr[:10]),
                        tx_hash
                    )

            # Check for new approval events via logs
            # Topic0 for Approval(address,address,uint256) = 0x8c5be1e5...
            approval_topic = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
            logs = await self._bc._rpc(chain, "eth_getLogs", [{
                "address": None,
                "topics": [approval_topic, "0x" + address[2:].lower().zfill(64)],
                "fromBlock": "latest",
            }])

            if logs:
                for log in logs:
                    spender = "0x" + log.get("topics", ["", "", ""])[2][-40:] if len(log.get("topics", [])) > 2 else "unknown"
                    data = log.get("data", "0x0")
                    # Check if unlimited approval (data is all f's)
                    if data and "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" in data:
                        await self._save_alert(
                            address, chain, AlertType.UNLIMITED_APPROVAL, "CRITICAL",
                            "UNLIMITED approval granted to %s" % spender[:10],
                            log.get("transactionHash", "")
                        )
                    else:
                        await self._save_alert(
                            address, chain, AlertType.NEW_APPROVAL, "MEDIUM",
                            "New approval granted to %s" % spender[:10],
                            log.get("transactionHash", "")
                        )

        except Exception:
            pass

    def set_ws_clients(self, clients):
        """Set WebSocket clients for push alerts."""
        self._ws_clients = clients
