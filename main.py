"""
══════════════════════════════════════════════════════════════
 Crypto Guardian — FastAPI Server
 PATCHED FOR GOAT + LANGGRAPH
 AI-powered on-chain security agent
 Run: uvicorn main:app --reload --port 3000
══════════════════════════════════════════════════════════════
"""

import os
import json
import asyncio
import re
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from services.blockchain import BlockchainService
from services.chains import CHAINS
from services.threat_intel import ThreatIntel
from services.safe_sdk import SafeSDK
from services.monitor import WalletMonitor
from services.wallet_store import wallet_store
from services.gas_optimizer import GasOptimizer
from services.tx_logger import tx_logger
from services.bridge import BridgeService
from services.memory_store import MemoryStore
from services.event_triggers import TriggerEngine
from services.rules_engine import RulesEngine
from services.alert_manager import AlertManager
from agent.core import init_agent, run_agent
from agent.goal_engine import GoalEngine
from agent.perception_loop import PerceptionLoop
from agent.acp_seller import ACPSkillCatalog
from agent.tools import ALL_TOOLS

# ── Rate limiter ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Globals ────────────────────────────────────────────────────
blockchain: BlockchainService = None
threat_intel: ThreatIntel = None
safe_sdk: SafeSDK = None
monitor: WalletMonitor = None
gas_optimizer: GasOptimizer = None
bridge_service: BridgeService = None
memory_store: MemoryStore = None
goal_engine: GoalEngine = None
perception_loop: PerceptionLoop = None
acp_catalog: ACPSkillCatalog = None
trigger_engine: TriggerEngine = None
rules_engine: RulesEngine = None
alert_manager: AlertManager = None
ws_clients: list[WebSocket] = []

# ── Address validation helper ────────────────────────────────
ADDRESS_REGEX = re.compile(r"^0x[a-fA-F0-9]{40}$")

def validate_address(address: str) -> str | None:
    """Validate Ethereum address format. Returns error message or None if valid."""
    if not ADDRESS_REGEX.match(address):
        return f"Invalid address format: {address}. Must be 0x followed by 40 hex characters."
    return None


# ── Lifespan (startup/shutdown) ──────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global blockchain, threat_intel, safe_sdk, monitor, gas_optimizer, bridge_service
    global memory_store, goal_engine, perception_loop, acp_catalog, trigger_engine
    global rules_engine, alert_manager

    key = os.getenv("ALCHEMY_API_KEY", "")
    blockchain = BlockchainService(key)

    # Intelligence Layer (v2)
    rules_engine = RulesEngine(scam_db=None)  # ScamDB is loaded inside ThreatIntel
    alert_manager = AlertManager()

    threat_intel = ThreatIntel(blockchain, rules_engine=rules_engine)
    # Wire scam_db into rules engine now that ThreatIntel has initialized it
    rules_engine._scam_db = threat_intel.scam_db

    safe_sdk = SafeSDK(blockchain)
    monitor = WalletMonitor(blockchain, threat_intel, alert_manager=alert_manager)
    gas_optimizer = GasOptimizer(blockchain)
    bridge_service = BridgeService()

    # Phase 4: Persistent Memory
    memory_store = MemoryStore()

    # Phase 1: Goal Engine + Perception Loop
    goal_engine = GoalEngine()
    await monitor.start()
    init_agent(blockchain, threat_intel, safe_sdk)

    # Perception loop (autonomous brain) — now with triage architecture
    perception_loop = PerceptionLoop(
        goal_engine=goal_engine,
        blockchain_service=blockchain,
        threat_intel=threat_intel,
        memory_store=memory_store,
        monitor=monitor,
        alert_manager=alert_manager,
        rules_engine=rules_engine,
        interval=int(os.getenv("PERCEPTION_INTERVAL", "120")),
    )

    # Wire run_agent as the thinking function for the perception loop
    async def agent_fn(message, thread_id="autonomous"):
        return await run_agent(message=message, thread_id=thread_id)
    perception_loop.set_agent_fn(agent_fn)
    await perception_loop.start()

    # Phase 2: ACP Skill Catalog
    acp_catalog = ACPSkillCatalog(ALL_TOOLS)

    # Phase 3: Event Triggers
    trigger_engine = TriggerEngine(perception_loop)

    re_stats = rules_engine.get_stats()
    print(f"\n\U0001f6e1\ufe0f  Crypto Guardian is live at http://localhost:{os.getenv('PORT', '3000')}")
    print(f"   Chains: {', '.join(CHAINS.keys())}")
    print(f"   Mode: AUTONOMOUS")
    print(f"   Agent: LangGraph + GOAT session keys")
    print(f"   Perception: Triage loop (every {os.getenv('PERCEPTION_INTERVAL', '120')}s)")
    print(f"   Goals: {goal_engine.get_stats()['active']} active")
    print(f"   ACP: {len(ALL_TOOLS)} skills listed for agent-to-agent commerce")
    print(f"   Memory: Persistent (SQLite)")
    print(f"   Intelligence: v2 (rules engine + confidence scoring + alert manager)")
    print(f"   Protocol Registry: {re_stats['totalProtocols']} verified across {len(re_stats['supportedChains'])} chains")
    print(f"   Alert Manager: dedup {alert_manager.DEDUP_WINDOW_SECONDS//60}min, cooldown {alert_manager.COOLDOWN_SECONDS//60}min\n")

    yield

    await perception_loop.stop()
    await monitor.stop()
    await bridge_service.close()
    await blockchain.close()


app = FastAPI(title="Crypto Guardian", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Health check (Railway deployment) ────────────────────────
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "agent": "Crypto Guardian",
        "tools": len(ALL_TOOLS),
        "mode": perception_loop.get_status()["mode"] if perception_loop else "reactive",
        "goals": goal_engine.get_stats() if goal_engine else {},
        "memory": memory_store.get_stats() if memory_store else {},
        "perception": perception_loop.get_status() if perception_loop else {},
    }


# ── Request Models ───────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str
    sessionId: str = "default"
    walletAddress: str | None = None
    chain: str = "ethereum"

class PhishingRequest(BaseModel):
    input: str
    type: str = "auto"

class GuardianRequest(BaseModel):
    address: str
    chains: list[str] = ["ethereum"]

class SimulateRequest(BaseModel):
    tx: dict
    chain: str = "ethereum"

class ScamReportRequest(BaseModel):
    address: str
    reason: str
    category: str = "user_report"


# ═══════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════

# ── Chat: Natural language → LangGraph agent ──────────────────
@app.post("/api/chat")
@limiter.limit("30/minute")
async def chat(req: ChatRequest, request: Request):
    # F3: Seed phrase blocker - block BEFORE hitting LLM
    import re as _re
    msg = req.message.strip()
    # Detect 12/24 word seed phrases
    words = msg.split()
    if len(words) in (12, 15, 18, 21, 24) and all(_re.match(r'^[a-z]{3,8}$', w) for w in words):
        return {"reply": "BLOCKED: This looks like a seed phrase. I will NEVER process seed phrases. Never share these with anyone or any app. Your seed phrase controls your entire wallet.", "blocked": True}
    # Detect private keys
    if _re.search(r'0x[a-fA-F0-9]{64}', msg):
        return {"reply": "BLOCKED: This looks like a private key. I will NEVER process private keys. Never share these.", "blocked": True}
    # Detect seed phrase keywords with actual words following
    if _re.search(r'(?i)(seed phrase|recovery phrase|mnemonic|private key).*[a-z]{3,8}(\s+[a-z]{3,8}){5,}', msg):
        return {"reply": "BLOCKED: Detected seed phrase content. Never share your recovery words with anyone.", "blocked": True}
    try:
        result = await run_agent(
            message=req.message,
            wallet_address=req.walletAddress,
            chain=req.chain,
            thread_id=req.sessionId,
        )
        return result
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ── Full scan (all data for a wallet on a chain) ──────────────
@app.get("/api/scan/{address}/{chain}")
@limiter.limit("60/minute")
async def scan(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    data = await blockchain.full_scan(address, chain)
    # Log transactions for tax export
    if isinstance(data, dict) and "transactions" in data:
        tx_logger.log_transactions(address, chain, data["transactions"])
    return data


# ── Individual endpoints ──────────────────────────────────────
@app.get("/api/approvals/{address}/{chain}")
@limiter.limit("60/minute")
async def approvals(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    return await blockchain.get_approvals(address, chain)

@app.get("/api/transactions/{address}/{chain}")
@limiter.limit("60/minute")
async def transactions(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    txs = await blockchain.get_transactions(address, chain)
    # Log for tax export
    if isinstance(txs, list):
        tx_logger.log_transactions(address, chain, txs)
    elif isinstance(txs, dict) and "transfers" in txs:
        tx_logger.log_transactions(address, chain, txs["transfers"])
    return txs

@app.get("/api/balances/{address}/{chain}")
@limiter.limit("60/minute")
async def balances(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    return await blockchain.get_balances(address, chain)

@app.post("/api/simulate")
@limiter.limit("30/minute")
async def simulate(req: SimulateRequest, request: Request):
    if req.chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {req.chain}"})
    return await blockchain.simulate_transaction(req.tx, req.chain)

@app.get("/api/nfts/{address}/{chain}")
@limiter.limit("60/minute")
async def nfts(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    return await blockchain.get_nfts(address, chain)

@app.get("/api/nft-approvals/{address}/{chain}")
@limiter.limit("60/minute")
async def nft_approvals(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    return await blockchain.get_nft_approvals(address, chain)


# -- Threat Engine endpoints --
@app.get("/api/contract-risk/{address}/{chain}")
@limiter.limit("30/minute")
async def contract_risk(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    report = await threat_intel.analyze_contract(address, chain)
    return report.to_dict()

@app.get("/api/token-security/{address}/{chain}")
@limiter.limit("30/minute")
async def token_security(address: str, chain: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    report = await threat_intel.analyze_token(address, chain)
    return report.to_dict()


# ── Risk score (multi-chain) ─────────────────────────────────
@app.get("/api/risk/{address}")
@limiter.limit("30/minute")
async def risk(address: str, request: Request):
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})

    chains = list(CHAINS.keys())
    results = await blockchain.multi_chain_scan(address, chains)

    total_a = unlimited = stale = total_t = nft_a = 0
    issues = []
    for r in results:
        if isinstance(r, Exception):
            continue
        for a in r.get("approvals", []):
            total_a += 1
            if a.get("isUnlimited"):
                unlimited += 1
                issues.append({"severity": "HIGH", "chain": r["chain"],
                    "message": f"Unlimited {a['tokenName']} approval to {a['spender'][:10]}…"})
            if a.get("ageInDays", 0) > 180:
                stale += 1
        total_t += len(r.get("transactions", []))
        nft_a += len(r.get("nftApprovals", []))

    score = min(
        min(unlimited * 15, 45) + min(stale * 5, 20) +
        min(nft_a * 10, 20) + (10 if total_a > 20 else 0),
        100
    )
    level = "LOW" if score < 20 else ("MEDIUM" if score < 50 else ("HIGH" if score < 75 else "CRITICAL"))

    return {
        "score": score, "level": level,
        "totalApprovals": total_a, "unlimitedApprovals": unlimited,
        "staleApprovals": stale, "nftApprovalForAll": nft_a,
        "totalTransactions": total_t,
        "issues": issues[:10],
    }


# ── Phishing check ───────────────────────────────────────────
@app.post("/api/phishing/check")
@limiter.limit("60/minute")
async def phishing_check(req: PhishingRequest, request: Request):
    from agent.tools import check_phishing
    result = await check_phishing.ainvoke({"input_text": req.input, "input_type": req.type})
    return json.loads(result)


# ── Scam Database APIs (Gap 2) ─────────────────────────────────
@app.get("/api/scam/check/{address}")
@limiter.limit("60/minute")
async def scam_check(address: str, request: Request):
    """Check if an address is in the scam database."""
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    result = threat_intel.scam_db.is_known_scam(address)
    if result:
        return {"found": True, "match": result}
    return {"found": False, "address": address, "message": "Address not found in scam database"}

@app.post("/api/scam/report")
@limiter.limit("10/minute")
async def scam_report(req: ScamReportRequest, request: Request):
    """Report a scam address for community flagging."""
    err = validate_address(req.address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    return threat_intel.scam_db.report_scam(req.address, req.reason, req.category)

@app.get("/api/scam/stats")
async def scam_stats():
    """Get scam database statistics."""
    return threat_intel.scam_db.get_stats()


# ── GOAT Chain Verification (Gap 3) ────────────────────────────
@app.get("/api/goat/verify")
async def goat_verify():
    """Verify the GOAT audit chain integrity."""
    from agent.tools import _goat_chain
    return _goat_chain.verify()


# ── Guardian mode ─────────────────────────────────────────────
@app.post("/api/guardian/start")
@limiter.limit("10/minute")
async def guardian_start(req: GuardianRequest, request: Request):
    err = validate_address(req.address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    from agent.tools import guardian_monitor
    result = await guardian_monitor.ainvoke({
        "action": "start", "address": req.address, "chains": ",".join(req.chains)
    })
    return json.loads(result)

@app.post("/api/guardian/stop")
@limiter.limit("10/minute")
async def guardian_stop(request: Request):
    from agent.tools import guardian_monitor
    result = await guardian_monitor.ainvoke({"action": "stop"})
    return json.loads(result)

@app.get("/api/guardian/status")
@limiter.limit("30/minute")
async def guardian_status(request: Request):
    from agent.tools import guardian_monitor
    result = await guardian_monitor.ainvoke({"action": "status"})
    return json.loads(result)


# ═══════════════════════════════════════════════════════════════
# WEBSOCKET — Real-time Guardian Alerts
# ═══════════════════════════════════════════════════════════════
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    try:
        await websocket.send_json({"type": "connected", "message": "Guardian WebSocket active"})
        while True:
            await websocket.receive_text()  # Keep alive
    except WebSocketDisconnect:
        ws_clients.remove(websocket)


# ── Multi-Wallet APIs (F7) ──────────────────────────────────
@app.post("/api/wallets")
@limiter.limit("30/minute")
async def add_wallet(request: Request):
    body = await request.json()
    address = body.get("address", "")
    label = body.get("label", "")
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    return wallet_store.add_wallet(address, label)

@app.delete("/api/wallets/{address}")
async def remove_wallet(address: str):
    wallet_store.remove_wallet(address)
    return {"removed": True}

@app.get("/api/wallets")
async def list_wallets():
    return {"wallets": wallet_store.list_wallets()}

@app.get("/api/wallets/scan-all")
@limiter.limit("10/minute")
async def scan_all_wallets(request: Request):
    return await wallet_store.scan_all(blockchain)

# ── Monitor APIs (F1) ───────────────────────────────────────
@app.post("/api/monitor/watch")
@limiter.limit("30/minute")
async def monitor_watch(request: Request):
    body = await request.json()
    address = body.get("address", "")
    chains = body.get("chains", ["ethereum"])
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    monitor.watch(address, chains)
    return {"watching": True, "address": address, "chains": chains}

@app.post("/api/monitor/unwatch")
async def monitor_unwatch(request: Request):
    body = await request.json()
    monitor.unwatch(body.get("address", ""))
    return {"unwatched": True}

@app.get("/api/monitor/alerts")
async def monitor_alerts(address: str = None):
    return {"alerts": monitor.get_alerts(address)}

# ── Gas APIs (F4) ────────────────────────────────────────────
@app.get("/api/gas/compare")
@limiter.limit("30/minute")
async def gas_compare(request: Request):
    return await gas_optimizer.compare_chains()

@app.get("/api/gas/{chain}")
@limiter.limit("60/minute")
async def gas_price(chain: str, request: Request):
    if chain not in CHAINS:
        return JSONResponse(status_code=400, content={"error": f"Unsupported chain: {chain}"})
    price = await gas_optimizer.get_gas_price(chain)
    history = await gas_optimizer.get_fee_history(chain)
    timing = gas_optimizer.suggest_timing(chain)
    return {"price": price, "history": history, "timing": timing}

# ── Bridge APIs (F5) ─────────────────────────────────────────
@app.get("/api/bridge/quote")
@limiter.limit("20/minute")
async def bridge_quote(request: Request, fromChain: str = "ethereum", toChain: str = "base",
                       token: str = "ETH", amount: float = 1.0):
    return await bridge_service.find_route(fromChain, toChain, token, amount)

# ── Tax Report APIs (F8 — Advanced) ──────────────────────────
@app.get("/api/export/csv/{address}")
async def export_csv(address: str):
    """Koinly Universal CSV export with proper format."""
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    csv_data = tx_logger.export_koinly_csv(address)
    from starlette.responses import Response
    return Response(content=csv_data, media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={address[:10]}_koinly.csv"})

@app.get("/api/export/summary/{address}")
async def export_summary(address: str):
    """Enhanced P&L summary with chain breakdown and income classification."""
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    return tx_logger.get_summary(address)

@app.get("/api/export/gains/{address}")
@limiter.limit("20/minute")
async def capital_gains(address: str, request: Request, method: str = "FIFO"):
    """Capital gains report with cost basis method (FIFO/LIFO/HIFO)."""
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    return tx_logger.calculate_gains(address, method=method)

@app.get("/api/export/income/{address}")
@limiter.limit("20/minute")
async def income_report(address: str, request: Request):
    """Income report: staking rewards, airdrops, mining, interest."""
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    return tx_logger.get_income_report(address)

@app.get("/api/export/harvesting/{address}")
@limiter.limit("20/minute")
async def tax_harvesting(address: str, request: Request):
    """Tax-loss harvesting suggestions."""
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    return tx_logger.get_harvesting_suggestions(address)

@app.get("/api/export/simulate/{address}")
@limiter.limit("20/minute")
async def simulate_tax(address: str, request: Request,
                       country: str = "US", income: float = 50000):
    """Full country-specific tax simulation with real 2025/2026 rates."""
    err = validate_address(address)
    if err:
        return JSONResponse(status_code=400, content={"error": err})
    return tx_logger.simulate_tax(address, country=country, annual_income=income)

@app.get("/api/export/countries")
async def supported_countries():
    """List supported countries for tax simulation."""
    from services.tx_logger import COUNTRY_TAX_RULES
    return {
        "countries": [
            {"code": code, "name": rules["name"], "currency": rules["currency"]}
            for code, rules in COUNTRY_TAX_RULES.items()
        ]
    }


# ═══════════════════════════════════════════════════════════════
# WEBSOCKET — Real-time alert stream  // ADDED FOR FINAL VERSION
# ═══════════════════════════════════════════════════════════════
@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    """Real-time alert stream for the frontend."""
    await websocket.accept()
    monitor.register_ws(websocket)
    try:
        while True:
            # Keep connection alive; client can also send messages
            data = await websocket.receive_text()
            # Optional: handle client commands like {"action":"ping"}
            if data:
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        monitor.unregister_ws(websocket)
    except Exception:
        monitor.unregister_ws(websocket)




# ═══════════════════════════════════════════════════════════════
#  AUTONOMOUS AGENT APIs — Goals, ACP, Webhooks, Memory
# ═══════════════════════════════════════════════════════════════

# ── Goal Management ──────────────────────────────────────────
class GoalRequest(BaseModel):
    type: str = "protect_wallet"
    target: str = ""
    chains: list[str] = ["ethereum"]
    priority: int = 5
    description: str = ""

@app.get("/api/goals")
async def list_goals():
    return {"goals": goal_engine.list_goals() if goal_engine else []}

@app.post("/api/goals")
async def add_goal(req: GoalRequest):
    if not goal_engine:
        return JSONResponse(status_code=503, content={"error": "Goal engine not initialized"})
    goal = goal_engine.add_goal(req.type, req.target, req.chains, req.priority, req.description)
    return {"status": "created", "goal": goal.to_dict()}

@app.delete("/api/goals/{goal_id}")
async def remove_goal(goal_id: str):
    if not goal_engine:
        return JSONResponse(status_code=503, content={"error": "Goal engine not initialized"})
    removed = goal_engine.remove_goal(goal_id)
    return {"status": "removed" if removed else "not_found", "goalId": goal_id}


# ── Perception Loop Status ───────────────────────────────────
@app.get("/api/perception/status")
async def perception_status():
    return perception_loop.get_status() if perception_loop else {"running": False, "mode": "reactive"}

@app.post("/api/perception/trigger")
async def trigger_perception(request: Request):
    """Manually trigger the perception loop with custom event data."""
    body = await request.json()
    if perception_loop:
        perception_loop.trigger_event(body.get("type", "MANUAL"), body.get("data", {}))
        return {"status": "triggered"}
    return JSONResponse(status_code=503, content={"error": "Perception loop not running"})


# ── Intelligence Layer (v2) API ──────────────────────────────
@app.get("/api/intelligence/stats")
async def intelligence_stats():
    """Get intelligence layer stats: rules engine, alert manager, confidence."""
    result = {}
    if rules_engine:
        result["rulesEngine"] = rules_engine.get_stats()
    if alert_manager:
        result["alertManager"] = alert_manager.get_stats()
    if perception_loop:
        status = perception_loop.get_status()
        result["perception"] = {
            "llmCallsTotal": status.get("llmCallsTotal", 0),
            "llmCallsSkipped": status.get("llmCallsSkipped", 0),
            "llmSavingsPercent": status.get("llmSavingsPercent", 0),
        }
    return result

@app.get("/api/intelligence/protocols/{chain}")
async def intelligence_protocols(chain: str):
    """Get verified protocols for a specific chain."""
    if not rules_engine:
        return {"protocols": {}}
    all_protocols = rules_engine.get_all_protocols()
    chain_protocols = all_protocols["chains"].get(chain, {})
    return {"chain": chain, "count": len(chain_protocols), "protocols": chain_protocols}

@app.get("/api/intelligence/alerts")
async def intelligence_alerts(wallet: str = None, limit: int = 20, action: str = None):
    """Get alert history from the AlertManager."""
    if not alert_manager:
        return {"alerts": []}
    alerts = alert_manager.get_recent_alerts(wallet=wallet, limit=limit, action_filter=action)
    return {"alerts": alerts, "stats": alert_manager.get_stats()}

@app.get("/api/intelligence/classify/{address}/{chain}")
async def intelligence_classify(address: str, chain: str = "ethereum"):
    """Classify an address using the rules engine."""
    if not rules_engine:
        return {"error": "Rules engine not initialized"}
    trust, info = rules_engine.classify(address, chain)
    return {
        "address": address,
        "chain": chain,
        "trust": trust.value,
        "protocol": {"name": info.name, "category": info.category.value, "trustLevel": info.trust_level} if info else None,
    }


# ── ACP (Agent Commerce Protocol) ────────────────────────────
@app.get("/api/acp/catalog")
async def acp_catalog_endpoint():
    """Skill catalog for agent-to-agent discovery."""
    return acp_catalog.get_catalog() if acp_catalog else {"skills": []}

@app.get("/api/acp/manifest.json")
async def acp_manifest():
    """Static manifest for ACP registry crawlers."""
    return acp_catalog.get_manifest() if acp_catalog else {}

@app.post("/api/acp/execute")
async def acp_execute(request: Request):
    """Execute a skill — called by external agents hiring our services."""
    if not acp_catalog:
        return JSONResponse(status_code=503, content={"error": "ACP not initialized"})
    body = await request.json()
    skill_id = body.get("skill", body.get("skill_id", ""))
    params = body.get("params", body.get("parameters", {}))
    if not skill_id:
        return JSONResponse(status_code=400, content={"error": "Missing 'skill' field"})
    result = await acp_catalog.execute_skill(skill_id, params)
    return result

@app.get("/api/acp/stats")
async def acp_stats():
    return acp_catalog.get_stats() if acp_catalog else {}


# ── Webhooks (Event Triggers) ────────────────────────────────
@app.post("/api/webhooks/alchemy")
async def alchemy_webhook(request: Request):
    """Receive Alchemy webhook notifications → triggers autonomous reasoning."""
    if not trigger_engine:
        return JSONResponse(status_code=503, content={"error": "Trigger engine not initialized"})
    body = await request.json()
    result = trigger_engine.process_alchemy_webhook(body)
    return result

@app.post("/api/webhooks/custom")
async def custom_webhook(request: Request):
    """Generic webhook receiver for external systems."""
    if not trigger_engine:
        return JSONResponse(status_code=503, content={"error": "Trigger engine not initialized"})
    body = await request.json()
    result = trigger_engine.process_custom_webhook(body)
    return result

@app.get("/api/webhooks/stats")
async def webhook_stats():
    return trigger_engine.get_stats() if trigger_engine else {}


# ── Memory ───────────────────────────────────────────────────
@app.get("/api/memory/stats")
async def memory_stats():
    return memory_store.get_stats() if memory_store else {}

@app.get("/api/memory/wallet/{address}")
async def get_wallet_memory(address: str):
    if not memory_store:
        return JSONResponse(status_code=503, content={"error": "Memory not initialized"})
    profile = memory_store.get_wallet_profile(address)
    incidents = memory_store.get_incidents(address, limit=10)
    context = memory_store.get_context_for_wallet(address)
    return {"profile": profile, "incidents": incidents, "context": context}

@app.get("/api/memory/incidents")
async def get_all_incidents():
    return {"incidents": memory_store.get_incidents(limit=20) if memory_store else []}


# ═══════════════════════════════════════════════════════════════
# AGENT DISCOVERY — .well-known/ai-plugin.json
# ═══════════════════════════════════════════════════════════════
@app.get("/.well-known/ai-plugin.json")
async def ai_plugin():
    """Standard agent discovery file — crawlers and other agents look for this."""
    return FileResponse("public/.well-known/ai-plugin.json", media_type="application/json")


# ═══════════════════════════════════════════════════════════════
# STATIC FILES — Serve the frontend dashboard
# ═══════════════════════════════════════════════════════════════
app.mount("/css", StaticFiles(directory="public/css"), name="css")
app.mount("/js", StaticFiles(directory="public/js"), name="js")

@app.get("/")
async def index():
    return FileResponse("public/index.html")


# ── Run with: python main.py ─────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "3000"))
    is_dev = os.getenv("RAILWAY_ENVIRONMENT") is None  # Only reload locally
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=is_dev)
