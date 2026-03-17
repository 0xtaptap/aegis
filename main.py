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
from agent.core import init_agent, run_agent

# ── Rate limiter ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Globals ──────────────────────────────────────────────────
blockchain: BlockchainService = None
threat_intel: ThreatIntel = None
safe_sdk: SafeSDK = None
monitor: WalletMonitor = None
gas_optimizer: GasOptimizer = None
bridge_service: BridgeService = None
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
    key = os.getenv("ALCHEMY_API_KEY", "")
    blockchain = BlockchainService(key)
    threat_intel = ThreatIntel(blockchain)
    safe_sdk = SafeSDK(blockchain)
    monitor = WalletMonitor(blockchain, threat_intel)
    gas_optimizer = GasOptimizer(blockchain)
    bridge_service = BridgeService()
    await monitor.start()
    init_agent(blockchain, threat_intel, safe_sdk)
    print(f"\n🛡️  Crypto Guardian is live at http://localhost:{os.getenv('PORT', '3000')}")
    print(f"   Chains: {', '.join(CHAINS.keys())}")
    print(f"   Mode: READ-ONLY")
    print(f"   Agent: LangGraph + GOAT session keys")
    print(f"   Threat Engine: Own (6 modules, 0 external APIs)")
    print(f"   Safe SDK: Transaction builder active")
    print(f"   Sessions: SQLite persistent\n")
    yield
    await monitor.stop()
    await bridge_service.close()
    await blockchain.close()


app = FastAPI(title="Crypto Guardian", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Health check (Railway deployment) ────────────────────────
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "agent": "Crypto Guardian", "tools": 22}


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
# VIRTUALS ACP — OpenClaw skill export  // ADDED FOR FINAL VERSION
# ═══════════════════════════════════════════════════════════════
@app.get("/api/acp/skills")
async def acp_skills():
    """OpenClaw-compatible skill schema for Virtuals agent discovery."""
    from agent.tools import ALL_TOOLS
    skills = []
    for t in ALL_TOOLS:
        params = {}
        if hasattr(t, 'args_schema') and t.args_schema:
            for name, field in t.args_schema.model_fields.items():
                params[name] = {
                    "type": field.annotation.__name__ if hasattr(field.annotation, '__name__') else str(field.annotation),
                    "required": field.is_required(),
                    "description": field.description or "",
                    "default": field.default if field.default is not None else None,
                }
        skills.append({
            "id": f"crypto-guardian:{t.name}",
            "name": t.name,
            "description": t.description or "",
            "parameters": params,
            "category": _tool_category(t.name),
            "pricing": {"model": "free", "cost": 0},
            "version": "2.0.0",
        })
    return {"agent": "Crypto Guardian", "protocol": "OpenClaw/ACP", "version": "2.0.0", "skills": skills}

def _tool_category(name):
    cats = {
        "scan_approvals": "security", "simulate_tx": "security", "check_threats": "security",
        "check_phishing": "security", "risk_score": "security", "check_contract": "security",
        "revoke_risky": "execution", "limited_revoke": "execution", "limited_execute": "execution",
        "create_session_key": "session", "guardian_monitor": "monitoring", "on_chain_log": "audit",
        "check_gas": "data", "find_bridge_route": "data", "explain_term": "education",
        "tax_simulate": "tax", "yield_optimizer": "defi", "airdrop_checker": "defi",
        "expose_skills": "acp",
    }
    return cats.get(name, "general")

@app.post("/api/acp/execute")
@limiter.limit("30/minute")
async def acp_execute(request: Request):
    """Allow external Virtuals agents to call any tool by name."""
    body = await request.json()
    tool_name = body.get("tool", "")
    args = body.get("args", {})
    from agent.tools import ALL_TOOLS
    tool_map = {t.name: t for t in ALL_TOOLS}
    if tool_name not in tool_map:
        return JSONResponse(status_code=404, content={"error": f"Tool '{tool_name}' not found"})
    try:
        result = await tool_map[tool_name].ainvoke(args)
        return {"tool": tool_name, "result": json.loads(result) if isinstance(result, str) else result}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


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
