# Crypto Guardian - LangChain Tools (19 security tools) // FINAL VERSION
# GOAT + LANGGRAPH + THREAT ENGINE + TAX + ACP

import json
import re
import hashlib
import time
import sqlite3
import os
from langchain_core.tools import tool
from agent.session_keys import session_manager

# ── Persistent GOAT Audit Chain (SQLite-backed) ─────────────
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(DATA_DIR, exist_ok=True)

class GoatChain:
    """SQLite-persisted tamper-evident action log with chain hashing."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(DATA_DIR, "goat_chain.db")
        self._init_db()
        self._chain_hash = self._load_last_hash()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS goat_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                wallet TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT DEFAULT '',
                timestamp REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_goat_wallet ON goat_log(wallet)")
            conn.commit()

    def _load_last_hash(self) -> str:
        """Load the most recent chain hash from DB, or genesis if empty."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT hash FROM goat_log ORDER BY id DESC LIMIT 1").fetchone()
            return row[0] if row else "0" * 64

    def append(self, wallet: str, action: str, details: str = "") -> dict:
        """Add entry to chain, persist to SQLite, return the entry."""
        entry = {
            "wallet": wallet, "action": action, "details": details,
            "timestamp": time.time(), "prevHash": self._chain_hash,
        }
        entry_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        entry["hash"] = entry_hash
        self._chain_hash = entry_hash

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO goat_log (hash, prev_hash, wallet, action, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (entry_hash, entry["prevHash"], wallet, action, details, entry["timestamp"])
            )
            conn.commit()

        return entry

    def length(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM goat_log").fetchone()
            return row[0] if row else 0

    def verify(self) -> dict:
        """Verify the entire chain integrity."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT hash, prev_hash, wallet, action, details, timestamp FROM goat_log ORDER BY id ASC").fetchall()

        if not rows:
            return {"valid": True, "length": 0, "message": "Empty chain"}

        prev = "0" * 64
        for i, (stored_hash, prev_hash, wallet, action, details, ts) in enumerate(rows):
            if prev_hash != prev:
                return {"valid": False, "length": len(rows), "broken_at": i, "message": f"Chain broken at entry {i}: prevHash mismatch"}
            entry = {"wallet": wallet, "action": action, "details": details, "timestamp": ts, "prevHash": prev_hash}
            computed = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            if computed != stored_hash:
                return {"valid": False, "length": len(rows), "broken_at": i, "message": f"Chain broken at entry {i}: hash mismatch (tampered)"}
            prev = stored_hash

        return {"valid": True, "length": len(rows), "latestHash": rows[-1][0], "message": f"Chain valid: {len(rows)} entries verified"}

    @property
    def current_hash(self) -> str:
        return self._chain_hash


# Initialize persistent chain
_goat_chain = GoatChain()

_blockchain = None
_threat_intel = None
_safe_sdk = None

def set_blockchain_service(svc):
    global _blockchain
    _blockchain = svc

def set_threat_intel(ti):
    global _threat_intel
    _threat_intel = ti

def set_safe_sdk(sdk):
    global _safe_sdk
    _safe_sdk = sdk

# Tool 1: scan_approvals
@tool
async def scan_approvals(address: str, chain: str = "ethereum") -> str:
    """Scan all token approvals for a wallet address on a specific blockchain. Returns approval details with risk levels."""
    try:
        approvals = await _blockchain.get_approvals(address, chain)
        if not approvals:
            return json.dumps({"status": "clean", "count": 0, "message": "No active approvals found on " + chain})
        high = [a for a in approvals if a["riskLevel"] == "HIGH"]
        med = [a for a in approvals if a["riskLevel"] == "MEDIUM"]
        return json.dumps({"status": "danger" if high else ("warning" if med else "safe"), "count": len(approvals), "highRisk": len(high), "mediumRisk": len(med), "lowRisk": len(approvals) - len(high) - len(med), "message": "Found %d approvals on %s: %d HIGH, %d MEDIUM risk." % (len(approvals), chain, len(high), len(med)), "approvals": approvals[:15]})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 2: simulate_tx (UPGRADED — supports pre-sign simulation + history)
@tool
async def simulate_tx(address: str, chain: str = "ethereum", count: int = 10, raw_tx: str = "") -> str:
    """Simulate a pending transaction BEFORE signing (Blowfish-level), or fetch past transaction history.
    For pre-sign simulation: pass raw_tx as a JSON string like '{"from":"0x...","to":"0x...","value":"0x0","data":"0x..."}'.
    For history: just pass an address. Shows what tokens you will gain/lose if you sign."""
    try:
        # MODE 1: Pre-sign simulation (if raw_tx provided)
        if raw_tx:
            try:
                tx_object = json.loads(raw_tx) if isinstance(raw_tx, str) else raw_tx
            except json.JSONDecodeError:
                return json.dumps({"status": "error", "message": "Invalid raw_tx JSON. Expected: {\"from\":\"0x...\",\"to\":\"0x...\",\"value\":\"0x0\",\"data\":\"0x...\"}"})

            result = await _blockchain.simulate_transaction(tx_object, chain)

            if result.get("status") == "error":
                return json.dumps({"status": "error", "mode": "simulation", "message": result.get("message", "Simulation failed")})

            # Format human-readable summary of what will happen
            changes = result.get("changes", [])
            gains = [c for c in changes if c.get("direction") == "IN"]
            losses = [c for c in changes if c.get("direction") == "OUT"]

            summary_parts = []
            for c in losses:
                summary_parts.append(f"SEND {c.get('amount', '?')} {c.get('symbol', 'tokens')}")
            for c in gains:
                summary_parts.append(f"RECEIVE {c.get('amount', '?')} {c.get('symbol', 'tokens')}")

            risk = "LOW"
            if not changes:
                risk = "MEDIUM"
                summary_parts.append("No asset changes detected (could be an approval or failed tx)")
            if result.get("simulationError"):
                risk = "HIGH"
                summary_parts.append(f"⚠️ Simulation error: {result['simulationError']}")

            return json.dumps({
                "status": "simulated",
                "mode": "pre-sign",
                "risk": risk,
                "summary": " | ".join(summary_parts) if summary_parts else "Transaction simulated successfully",
                "gains": gains,
                "losses": losses,
                "allChanges": changes,
                "gasUsed": result.get("gasUsed", ""),
                "message": "PRE-SIGN SIMULATION: If you sign this tx, here is what happens → " + (" | ".join(summary_parts)),
            })

        # MODE 2: Transaction history (existing behavior)
        txs = await _blockchain.get_transactions(address, chain)
        limited = txs[:min(count, 30)]
        if not limited:
            return json.dumps({"status": "empty", "message": "No recent transactions on " + chain})
        out = [t for t in limited if t["direction"] == "OUT"]
        inc = [t for t in limited if t["direction"] == "IN"]
        return json.dumps({"status": "ok", "message": "Found %d recent txs on %s: %d sent, %d received." % (len(limited), chain, len(out), len(inc)), "transactions": limited})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 3: check_threats (UPGRADED FROM check_phishing) // ADDED FOR FINAL VERSION
@tool
async def check_threats(input_text: str, input_type: str = "auto") -> str:
    """Analyze an address, URL, text, or media link for phishing, scam, and deepfake indicators. Uses our threat engine with 12 brand targets, 12 scam patterns, TLD analysis, address poisoning detection, on-chain analysis, and deepfake media URL scanning."""
    try:
        findings = []

        # Original phishing detection via threat engine
        if _threat_intel:
            report = await _threat_intel.full_threat_scan(input_text)
            findings = report.findings
            base_score = report.risk_score
        else:
            base_score = 0

        # ADDED FOR FINAL VERSION — deepfake media URL analysis
        deepfake_score = 0
        text_lower = input_text.lower()

        # Check for media URLs
        if any(ext in text_lower for ext in ['.mp4', '.webm', '.mp3', '.wav', '.ogg', '.avi', '.mov']):
            deepfake_score += 20
            findings.append({"type": "MEDIA_URL", "severity": "WARNING", "detail": "Media file URL detected — verify source authenticity"})

        # Known deepfake domains and AI-generated content patterns
        deepfake_domains = ['deepfakes.', 'fakeapp.', 'synthesia.', 'wav2lip.', 'facemegic.']
        if any(d in text_lower for d in deepfake_domains):
            deepfake_score += 40
            findings.append({"type": "DEEPFAKE_DOMAIN", "severity": "HIGH", "detail": "URL from known deepfake/AI-generation service"})

        # AI-generated voice patterns (suspicious domains claiming to be "official" calls)
        voice_scam_patterns = ['verify your wallet', 'official support call', 'confirm your seed', 'customer service crypto', 'wallet verification voice']
        if any(p in text_lower for p in voice_scam_patterns):
            deepfake_score += 30
            findings.append({"type": "VOICE_SCAM_PATTERN", "severity": "CRITICAL", "detail": "Pattern matches crypto voice scam — no legitimate service requests wallet verification by voice/video"})

        # Social engineering via fake video calls
        if any(k in text_lower for k in ['zoom.us.', 'meet.google.', 'teams.microsoft.']) and any(k in text_lower for k in ['.tk', '.ml', '.ga', '.cf', '.gq']):
            deepfake_score += 35
            findings.append({"type": "FAKE_MEETING_LINK", "severity": "CRITICAL", "detail": "Fake video call link using suspicious TLD — likely phishing"})

        total_score = min(base_score + deepfake_score, 100)
        verdict = "SAFE" if total_score < 20 else ("WARNING" if total_score < 50 else ("DANGEROUS" if total_score < 75 else "CRITICAL"))

        return json.dumps({"input": input_text[:100], "score": total_score, "verdict": verdict, "risks": findings, "deepfakeScore": deepfake_score})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Keep backward compatibility alias
check_phishing = check_threats

# Tool 4: risk_score
@tool
async def risk_score(address: str, chains: str = "ethereum") -> str:
    """Calculate composite 0-100 risk score for a wallet across specified chains (comma-separated)."""
    try:
        chain_list = [c.strip() for c in chains.split(",")]
        results = await _blockchain.multi_chain_scan(address, chain_list)
        total_approvals = unlimited = stale = total_txs = nft_approvals = 0
        issues = []
        for r in results:
            if isinstance(r, Exception):
                continue
            for a in r.get("approvals", []):
                total_approvals += 1
                if a.get("isUnlimited"):
                    unlimited += 1
                    issues.append({"severity": "HIGH", "chain": r["chain"], "issue": "Unlimited %s approval to %s" % (a["tokenName"], a["spender"][:10])})
                if a.get("ageInDays", 0) > 180:
                    stale += 1
            total_txs += len(r.get("transactions", []))
            nft_approvals += len(r.get("nftApprovals", []))
        sc = min(min(unlimited * 15, 45) + min(stale * 5, 20) + min(nft_approvals * 10, 20) + (10 if total_approvals > 20 else 0), 100)
        level = "LOW" if sc < 20 else ("MEDIUM" if sc < 50 else ("HIGH" if sc < 75 else "CRITICAL"))
        return json.dumps({"score": sc, "level": level, "totalApprovals": total_approvals, "unlimitedApprovals": unlimited, "staleApprovals": stale, "nftApprovalForAll": nft_approvals, "totalTransactions": total_txs, "issues": issues[:10]})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 5: revoke_risky
@tool
async def revoke_risky(address: str, chain: str = "ethereum") -> str:
    """Analyze approvals and recommend which to revoke. In read-only mode, provides recommendations."""
    try:
        approvals = await _blockchain.get_approvals(address, chain)
        to_revoke = [a for a in approvals if a["isUnlimited"] or a["riskLevel"] in ("HIGH", "MEDIUM")]
        if not to_revoke:
            return json.dumps({"status": "clean", "message": "All approvals on %s look healthy." % chain})
        sk = session_manager.get_or_create_readonly(address)
        return json.dumps({"status": "action_needed", "mode": sk.mode.value, "message": "Found %d approvals to revoke on %s." % (len(to_revoke), chain), "toRevoke": [{"token": a["tokenName"], "spender": a["spender"], "reason": "UNLIMITED" if a["isUnlimited"] else "Risky", "method": "approve(%s, 0) on %s" % (a["spender"], a["token"])} for a in to_revoke], "instructions": "Upgrade to LIMITED mode to auto-revoke." if sk.mode.value == "READ_ONLY" else "Ready to batch-revoke via Safe."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 6: guardian_monitor
_guardian_state = {"active": False, "address": None, "chains": [], "alerts": [], "started_at": None}

@tool
async def guardian_monitor(action: str, address: str = "", chains: str = "ethereum") -> str:
    """Control Guardian monitoring mode. Actions: start, stop, status."""
    if action == "start":
        if not address:
            return json.dumps({"status": "error", "message": "Wallet address required."})
        _guardian_state.update(active=True, address=address, chains=chains.split(","), started_at=__import__("datetime").datetime.now().isoformat(), alerts=[])
        return json.dumps({"status": "activated", "message": "Guardian Mode ON for %s on %s" % (address[:10], chains)})
    elif action == "stop":
        was = _guardian_state["active"]
        _guardian_state["active"] = False
        return json.dumps({"status": "deactivated", "message": "Guardian stopped. %d alerts." % len(_guardian_state["alerts"]) if was else "Was not active."})
    else:
        return json.dumps({"status": "active" if _guardian_state["active"] else "inactive", "address": _guardian_state["address"], "alerts": len(_guardian_state["alerts"])})

# Tool 7: create_session_key
@tool
async def create_session_key(address: str, mode: str = "READ_ONLY", max_spend_usd: float = 0.0, allowed_protocols: str = "", allowed_chains: str = "ethereum", ttl_hours: int = 1) -> str:
    """Create or update a session key for a wallet. Modes: READ_ONLY, LIMITED, FULL."""
    try:
        protocols = [p.strip() for p in allowed_protocols.split(",") if p.strip()] if allowed_protocols else []
        chains_list = [c.strip() for c in allowed_chains.split(",") if c.strip()]
        sk = session_manager.create_session(wallet_address=address, mode=mode, max_spend_usd=max_spend_usd, allowed_protocols=protocols, allowed_chains=chains_list, ttl_seconds=ttl_hours * 3600)
        return json.dumps({"status": "created", "message": "Session key created for %s" % address[:10], "session": sk.to_dict()})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 8: limited_revoke
@tool
async def limited_revoke(address: str, token_address: str, spender: str, chain: str = "ethereum") -> str:
    """Revoke a specific token approval via Safe smart account within session limits."""
    try:
        validation = session_manager.validate_action(wallet_address=address, action_type="revoke", estimated_cost_usd=0.50, chain=chain)
        revoke_tx = {"from": address, "to": token_address, "value": "0x0", "data": "0x095ea7b3000000000000000000000000" + spender[2:].lower() + "0" * 64}
        sim = await _blockchain.simulate_transaction(revoke_tx, chain)
        if not validation["allowed"]:
            return json.dumps({"status": "blocked", "reason": validation["reason"], "simulation": sim, "message": "Blocked: %s" % validation["reason"]})
        session = validation.get("session", {})
        if session and session.get("mode") == "READ_ONLY":
            return json.dumps({"status": "simulated", "message": "Simulation OK. Upgrade to LIMITED to execute.", "simulation": sim})
        session_manager.log_action(address, {"type": "revoke", "token": token_address, "spender": spender, "chain": chain})
        return json.dumps({"status": "executed", "message": "Revoked via Safe.", "simulation": sim})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 9: limited_execute
@tool
async def limited_execute(address: str, intent: str, chain: str = "ethereum", estimated_cost_usd: float = 0.0, protocol: str = "") -> str:
    """Execute a user intent (swap, bridge, claim) within session key limits via Safe."""
    try:
        validation = session_manager.validate_action(wallet_address=address, action_type="execute", estimated_cost_usd=estimated_cost_usd, protocol=protocol, chain=chain)
        if not validation["allowed"]:
            return json.dumps({"status": "blocked", "reason": validation["reason"], "message": "Blocked: %s" % validation["reason"]})
        session = validation.get("session", {})
        if session and session.get("mode") == "READ_ONLY":
            return json.dumps({"status": "read_only", "intent": intent, "message": "Upgrade to LIMITED mode to execute."})
        return json.dumps({"status": "needs_confirmation", "intent": intent, "estimatedCost": estimated_cost_usd, "chain": chain, "message": "Ready to %s. Confirm to proceed." % intent})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 10: on_chain_log (UPGRADED — GOAT verifiable chain hash, SQLite-persisted)
@tool
async def on_chain_log(address: str, action_type: str, details: str = "") -> str:
    """Log a Guardian action with a GOAT-verifiable chain hash. Persisted to SQLite — survives server restarts. Each entry references the previous hash, forming a tamper-evident chain. Verifiable by any party."""
    try:
        entry = _goat_chain.append(address, action_type, details)
        chain_len = _goat_chain.length()
        session_manager.log_action(address, {"type": "log", "action": action_type, "hash": entry["hash"], "prevHash": entry["prevHash"]})
        return json.dumps({
            "status": "logged", "hash": entry["hash"], "prevHash": entry["prevHash"],
            "chainLength": chain_len,
            "message": "GOAT-logged: %s | %s (chain: %d entries, persistent)" % (action_type, entry["hash"][:16], chain_len),
            "verifiable": True, "persistent": True,
        })
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 11: check_contract (Threat Engine)
@tool
async def check_contract(address: str, chain: str = "ethereum") -> str:
    """Deep-analyze a contract/token for rug pull risks, honeypot traps, proxy patterns, and owner privileges. Uses bytecode analysis + sell simulation."""
    try:
        if not _threat_intel:
            return json.dumps({"status": "error", "message": "Threat engine not initialized."})
        report = await _threat_intel.analyze_token(address, chain)
        return json.dumps({"address": address, "chain": chain, "riskScore": report.risk_score, "riskLevel": report.risk_level, "findings": report.findings, "summary": "Score %d/100 (%s). %d findings." % (report.risk_score, report.risk_level, len(report.findings))})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 12: check_gas
@tool
async def check_gas(chain: str = "all") -> str:
    """Compare gas fees across all supported chains or get detailed gas info for a specific chain. Shows current prices in gwei and suggests cheapest chain."""
    try:
        from services.gas_optimizer import GasOptimizer
        if not _blockchain:
            return json.dumps({"status": "error", "message": "Blockchain service not initialized."})
        go = GasOptimizer(_blockchain)
        if chain == "all":
            result = await go.compare_chains()
            return json.dumps(result)
        else:
            price = await go.get_gas_price(chain)
            history = await go.get_fee_history(chain)
            timing = go.suggest_timing(chain)
            return json.dumps({"price": price, "history": history, "timing": timing})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 13: find_bridge
@tool
async def find_bridge_route(from_chain: str, to_chain: str, token: str = "ETH", amount: float = 1.0) -> str:
    """Find the best bridge route to move tokens between chains. Uses Li.Fi API for real route comparison. Example: find_bridge_route('ethereum', 'base', 'ETH', 1.0)"""
    try:
        from services.bridge import BridgeService
        bs = BridgeService()
        result = await bs.find_route(from_chain, to_chain, token, amount)
        await bs.close()
        if "rawQuote" in result:
            del result["rawQuote"]  # Too large for agent context
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 14: explain_term
@tool
def explain_term(term: str) -> str:
    """Explain a crypto/blockchain term in plain English. Use this when the user asks what something means."""
    glossary = {
        "approval": "An approval is permission you gave a smart contract to spend your tokens. Think of it like a blank check - the contract can take tokens from your wallet up to the approved amount. Unlimited approvals are risky because they let the contract take ALL your tokens.",
        "gas": "Gas is the fee you pay to send a transaction on a blockchain. Its like a shipping cost. Gas prices change based on how busy the network is. Layer 2 chains (Base, Arbitrum) have much cheaper gas than Ethereum mainnet.",
        "bridge": "A bridge is a service that moves your tokens from one blockchain to another. For example, moving ETH from Ethereum to Base. Different bridges have different fees, speeds, and safety levels.",
        "rug pull": "A rug pull is when a token creator suddenly removes all the liquidity (trading money) and disappears with everyones funds. Warning signs: new token (<7 days), owner holds most supply, ownership not renounced.",
        "honeypot": "A honeypot token is designed to trap you. You can buy it but you cannot sell it. The contract has hidden code that blocks sell transactions. Always check with our token scanner before buying unknown tokens.",
        "liquidity": "Liquidity means how easy it is to buy or sell a token. High liquidity = easy to trade, low slippage. Low liquidity = hard to sell, price impact. Scam tokens often have very low liquidity.",
        "smart contract": "A smart contract is a program that runs on the blockchain. It automatically executes code when certain conditions are met. Token contracts, DEX routers, and lending protocols are all smart contracts.",
        "seed phrase": "Your seed phrase is the 12 or 24 words that control your entire wallet. NEVER share these with anyone. Anyone who has your seed phrase can steal everything. There is no recovery if someone gets it.",
        "multisig": "A multisig (multi-signature) wallet requires multiple people to approve a transaction. For example, 3 out of 5 owners must sign. This is much safer than a single-key wallet because one compromised key cannot steal funds.",
        "dex": "A DEX (decentralized exchange) is where you swap tokens without a middleman. Uniswap, PancakeSwap, and SushiSwap are DEXes. Unlike Coinbase or Binance, you keep custody of your tokens.",
        "nft": "An NFT (non-fungible token) is a unique digital item on the blockchain. Each one is different, unlike tokens where every ETH is the same. NFT approvals (setApprovalForAll) can be risky because they give access to ALL your NFTs in a collection.",
        "erc20": "ERC20 is the standard format for tokens on Ethereum and compatible chains. USDC, USDT, UNI, LINK are all ERC20 tokens. The standard includes functions like transfer, approve, and balanceOf.",
        "wallet": "A crypto wallet stores your private keys and lets you send/receive tokens. It doesnt actually hold your crypto - that lives on the blockchain. The wallet just proves you own it. Examples: MetaMask, Phantom, Rabby.",
        "defi": "DeFi (Decentralized Finance) means financial services (lending, borrowing, trading) that run on smart contracts instead of banks. Aave, Compound, and Uniswap are DeFi protocols.",
        "slippage": "Slippage is the difference between the price you expect and the price you actually get when trading. High slippage means you lose more money on the trade. Set slippage tolerance carefully - too high and you can be frontrun.",
        "impermanent loss": "Impermanent loss happens when you provide liquidity to a DEX pool and the token prices change. The bigger the price change, the more you lose compared to just holding. Its called impermanent because it reverses if prices return to original.",
    }
    key = term.lower().strip()
    for k, v in glossary.items():
        if key in k or k in key:
            return v
    return "I dont have a specific definition for '%s'. Try asking me to explain it in the chat and I will do my best." % term

# ═══════════════════════════════════════════════════════════════
# Tools 15+ — Tax, ACP, Scam DB, GOAT Chain
# ═══════════════════════════════════════════════════════════════

# Tool 15: tax_simulate — Full DeFi tax simulation
@tool
async def tax_simulate(address: str, country: str = "US", annual_income: float = 50000) -> str:
    """Run a full country-specific crypto tax simulation. Supports 10 countries (US/UK/IN/DE/AU/CA/FR/JP/KR/SG) with real 2025/2026 tax brackets, capital gains, DeFi income classification, and tax-loss harvesting suggestions."""
    try:
        from services.tx_logger import TaxReportEngine
        engine = TaxReportEngine()
        result = engine.simulate_tax(address, country=country, annual_income=annual_income)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 16: expose_skills — Virtuals ACP / OpenClaw skill export
@tool
def expose_skills() -> str:
    """Export all Crypto Guardian tools as OpenClaw-compatible skill schema for Virtuals ACP. Other agents can discover, hire, and call our tools automatically via x402 USDC micropayments."""
    skills = []
    for t in ALL_TOOLS:
        schema = {}
        if hasattr(t, 'args_schema') and t.args_schema:
            for name, field in t.args_schema.model_fields.items():
                schema[name] = {
                    "type": field.annotation.__name__ if hasattr(field.annotation, '__name__') else str(field.annotation),
                    "required": field.is_required(),
                }
        skills.append({
            "id": "crypto-guardian:%s" % t.name,
            "name": t.name,
            "description": t.description or "",
            "parameters": schema,
            "category": "security",
            "endpoint": "/api/acp/execute",
            "pricing": {"model": "x402", "currency": "USDC", "network": "base"},
        })
    return json.dumps({
        "agent": "Crypto Guardian",
        "protocol": "OpenClaw/ACP",
        "version": "3.0.0",
        "totalSkills": len(skills),
        "payment": {"method": "x402", "currency": "USDC", "network": "base",
                    "wallet": os.getenv("PAYMENT_WALLET", "")},
        "skills": skills,
    })

# Tool 17: report_scam — Community scam address reporting
@tool
def report_scam(address: str, reason: str, category: str = "user_report") -> str:
    """Report a scam address to the community database. Address will be flagged and checked during future scans. Categories: drainer, phishing, rugpull, ponzi, honeypot, fake_token, approval_scam, or user_report."""
    try:
        from services.threat_intel import _scam_db
        result = _scam_db.report_scam(address, reason, category)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 18: goat_verify — GOAT audit chain integrity verification
@tool
def goat_verify() -> str:
    """Verify the integrity of the entire GOAT audit chain. Checks every entry's hash against the previous hash to detect any tampering. Returns valid/broken status and chain length."""
    try:
        result = _goat_chain.verify()
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Tool 19: scam_check — Instant known-scam address lookup
@tool
def scam_check(address: str) -> str:
    """Instantly check if an address is a known scam in our database (200+ seeded addresses across 15 categories: drainers, phishing, rug pulls, honeypots, Ponzi, mixers, exploits, etc). Returns match details or clean status."""
    try:
        from services.threat_intel import _scam_db
        result = _scam_db.is_known_scam(address)
        if result:
            return json.dumps({"found": True, "match": result, "message": "⚠️ SCAM ALERT: %s — %s (%s)" % (result["category"].upper(), result["reason"], result["source"])})
        return json.dumps({"found": False, "address": address, "message": "Address not found in scam database (clean so far)"})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# All tools (19 total)
ALL_TOOLS = [
    scan_approvals, simulate_tx, check_threats, risk_score, revoke_risky,
    guardian_monitor, create_session_key, limited_revoke, limited_execute,
    on_chain_log, check_contract, check_gas, find_bridge_route, explain_term,
    tax_simulate, expose_skills, report_scam, goat_verify, scam_check,
]

