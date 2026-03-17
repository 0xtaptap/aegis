"""
Crypto Guardian — ACP Seller + x402 Micropayment Commerce
Exposes all agent skills for agent-to-agent discovery and paid execution.
Other agents find us via /.well-known/ai-plugin.json and /api/acp/manifest.json
and pay in USDC on Base via x402.
"""

import json
import os
import time


class ACPSkillCatalog:
    """
    ACP skill catalog with x402 USDC micropayment support.
    Agents discover us → call /api/acp/execute → pay USDC to our Base wallet.
    """

    def __init__(self, all_tools: list):
        self._tools = {t.name: t for t in all_tools}
        self._call_count = 0
        self._revenue = 0.0
        self._call_log = []

        # Pricing per skill (USDC on Base)
        self._skill_meta = {
            # Security (high value)
            "scan_approvals":   {"category": "security",   "price_usdc": 0.01},
            "simulate_tx":     {"category": "security",   "price_usdc": 0.02},
            "check_threats":   {"category": "security",   "price_usdc": 0.01},
            "risk_score":      {"category": "security",   "price_usdc": 0.01},
            "scam_check":      {"category": "security",   "price_usdc": 0.005},
            "check_contract":  {"category": "security",   "price_usdc": 0.02},
            "report_scam":     {"category": "security",   "price_usdc": 0.0},
            # Execution
            "revoke_risky":    {"category": "execution",  "price_usdc": 0.02},
            "limited_revoke":  {"category": "execution",  "price_usdc": 0.01},
            "limited_execute": {"category": "execution",  "price_usdc": 0.02},
            "create_session_key": {"category": "execution", "price_usdc": 0.01},
            # Monitoring
            "guardian_monitor": {"category": "monitoring", "price_usdc": 0.005},
            "on_chain_log":    {"category": "audit",      "price_usdc": 0.0},
            "goat_verify":     {"category": "audit",      "price_usdc": 0.0},
            # Data
            "check_gas":       {"category": "data",       "price_usdc": 0.005},
            "find_bridge_route": {"category": "data",     "price_usdc": 0.005},
            "explain_term":    {"category": "education",  "price_usdc": 0.0},
            # Tax
            "tax_simulate":    {"category": "tax",        "price_usdc": 0.01},
            # Meta
            "expose_skills":   {"category": "meta",       "price_usdc": 0.0},
        }

    def _payment_wallet(self) -> str:
        return os.getenv("PAYMENT_WALLET", "")

    def get_catalog(self) -> dict:
        """Full ACP-compatible skill catalog for agent discovery."""
        skills = []
        for tool_name, tool in self._tools.items():
            meta = self._skill_meta.get(tool_name, {"category": "other", "price_usdc": 0.0})
            schema = {}
            if hasattr(tool, 'args_schema') and tool.args_schema:
                for name, field in tool.args_schema.model_fields.items():
                    schema[name] = {
                        "type": field.annotation.__name__ if hasattr(field.annotation, '__name__') else str(field.annotation),
                        "required": field.is_required(),
                        "default": str(field.default) if field.default is not None else None,
                    }
            skills.append({
                "id": "crypto-guardian:%s" % tool_name,
                "name": tool_name,
                "description": tool.description or "",
                "parameters": schema,
                "category": meta["category"],
                "pricing": {
                    "method": "x402",
                    "currency": "USDC",
                    "network": "base",
                    "cost": meta["price_usdc"],
                },
                "endpoint": "/api/acp/execute",
                "method": "POST",
            })

        return {
            "agent": {
                "name": "Crypto Guardian",
                "id": "crypto-guardian-aegis",
                "version": "3.0.0",
                "description": "On-chain AI security agent — scam detection, tx simulation, approval scanning, contract auditing. 19 hireable skills via x402 USDC micropayments.",
                "capabilities": ["security", "monitoring", "execution", "data", "tax"],
                "chains": ["ethereum", "polygon", "bsc", "arbitrum", "base", "optimism", "avalanche"],
            },
            "payment": {
                "method": "x402",
                "currency": "USDC",
                "network": "base",
                "wallet": self._payment_wallet(),
                "description": "Accepts x402 micropayments in USDC on Base. Send payment to wallet address with x402 header.",
            },
            "protocol": "ACP/OpenClaw",
            "acp_version": "1.0",
            "total_skills": len(skills),
            "skills": skills,
            "stats": {
                "total_calls": self._call_count,
                "total_revenue_usdc": self._revenue,
                "uptime": "live",
            },
        }

    async def execute_skill(self, skill_id: str, params: dict) -> dict:
        """Execute a skill by ID with given parameters. Returns tool result."""
        tool_name = skill_id.split(":")[-1] if ":" in skill_id else skill_id

        tool = self._tools.get(tool_name)
        if not tool:
            return {"status": "error", "message": "Unknown skill: %s" % skill_id,
                    "available": list(self._tools.keys())}

        try:
            self._call_count += 1
            meta = self._skill_meta.get(tool_name, {"price_usdc": 0.0})
            price = meta.get("price_usdc", 0.0)
            self._revenue += price

            # Execute the tool
            result = await tool.ainvoke(params)

            # Log the call
            self._call_log.append({
                "skill": tool_name, "params": str(params)[:100],
                "timestamp": time.time(), "success": True,
                "charged_usdc": price,
            })

            # Parse result
            try:
                parsed = json.loads(result) if isinstance(result, str) else result
            except (json.JSONDecodeError, TypeError):
                parsed = {"result": result}

            return {
                "status": "success",
                "skill": tool_name,
                "result": parsed,
                "billing": {
                    "charged": price,
                    "currency": "USDC",
                    "network": "base",
                    "wallet": self._payment_wallet(),
                    "method": "x402",
                },
            }

        except Exception as e:
            self._call_log.append({
                "skill": tool_name, "params": str(params)[:100],
                "timestamp": time.time(), "success": False, "error": str(e),
            })
            return {"status": "error", "skill": tool_name, "message": str(e)}

    def get_manifest(self) -> dict:
        """
        Full manifest for ACP registry crawlers and agent discovery.
        Served at /api/acp/manifest.json
        """
        wallet = self._payment_wallet()
        skills_summary = []
        for tool_name, tool in self._tools.items():
            meta = self._skill_meta.get(tool_name, {"category": "other", "price_usdc": 0.0})
            skills_summary.append({
                "id": "crypto-guardian:%s" % tool_name,
                "name": tool_name,
                "description": (tool.description or "")[:200],
                "category": meta["category"],
                "price_usdc": meta.get("price_usdc", 0.0),
            })

        return {
            "schema_version": "1.0",
            "agent": {
                "name": "Crypto Guardian",
                "id": "crypto-guardian-aegis",
                "version": "3.0.0",
                "description": "Autonomous on-chain AI security agent. Scans wallets, simulates transactions, detects scams, audits contracts, monitors threats 24/7 across 7 EVM chains.",
                "homepage": os.getenv("RAILWAY_PUBLIC_URL", "https://aegis-production-3685.up.railway.app"),
                "logo": "/img/logo.png",
            },
            "api": {
                "execute_url": "/api/acp/execute",
                "catalog_url": "/api/acp/catalog",
                "health_url": "/api/health",
                "webhook_url": "/api/webhooks/custom",
            },
            "payment": {
                "accepts": "x402",
                "currency": "USDC",
                "network": "base",
                "chain_id": 8453,
                "wallet": wallet,
                "description": "Accepts x402 micropayments in USDC on Base. All skills priced $0.005-$0.02 per call. Free tier available.",
            },
            "capabilities": ["security", "monitoring", "execution", "data", "tax", "audit"],
            "chains_supported": ["ethereum", "polygon", "bsc", "arbitrum", "base", "optimism", "avalanche"],
            "skills": skills_summary,
            "total_skills": len(skills_summary),
            "contact": {
                "protocol": "ACP/OpenClaw",
                "webhook": "/api/webhooks/custom",
            },
        }

    def get_stats(self) -> dict:
        return {
            "totalCalls": self._call_count,
            "totalRevenueUSDC": self._revenue,
            "recentCalls": self._call_log[-10:],
            "skillCount": len(self._tools),
            "paymentWallet": self._payment_wallet(),
        }
