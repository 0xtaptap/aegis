"""
Crypto Guardian — Virtuals ACP Seller
Exposes all agent skills as ACP-compatible services for agent-to-agent commerce.
Other Virtuals/ElizaOS/GOAT agents can discover and hire our security skills.
"""

import json
import time
from typing import Optional


class ACPSkillCatalog:
    """
    ACP (Agent Commerce Protocol) skill catalog.
    Registers all Crypto Guardian tools as purchasable services
    for the Virtuals agent marketplace.
    """

    def __init__(self, all_tools: list):
        self._tools = {t.name: t for t in all_tools}
        self._call_count = 0
        self._revenue = 0.0
        self._call_log = []

        # Define skill categories and pricing
        self._skill_meta = {
            # Security (high value)
            "scan_approvals":   {"category": "security", "price": 0.01, "tier": "premium"},
            "simulate_tx":     {"category": "security", "price": 0.02, "tier": "premium"},
            "check_threats":   {"category": "security", "price": 0.01, "tier": "premium"},
            "risk_score":      {"category": "security", "price": 0.01, "tier": "premium"},
            "scam_check":      {"category": "security", "price": 0.005, "tier": "standard"},
            "check_contract":  {"category": "security", "price": 0.02, "tier": "premium"},
            "report_scam":     {"category": "security", "price": 0.0, "tier": "free"},
            # Execution
            "revoke_risky":    {"category": "execution", "price": 0.02, "tier": "premium"},
            "limited_revoke":  {"category": "execution", "price": 0.01, "tier": "standard"},
            "limited_execute": {"category": "execution", "price": 0.02, "tier": "premium"},
            "create_session_key": {"category": "execution", "price": 0.01, "tier": "standard"},
            # Monitoring
            "guardian_monitor": {"category": "monitoring", "price": 0.005, "tier": "standard"},
            "on_chain_log":    {"category": "monitoring", "price": 0.0, "tier": "free"},
            "goat_verify":     {"category": "monitoring", "price": 0.0, "tier": "free"},
            # Data
            "check_gas":       {"category": "data", "price": 0.005, "tier": "standard"},
            "find_bridge_route": {"category": "data", "price": 0.005, "tier": "standard"},
            "explain_term":    {"category": "education", "price": 0.0, "tier": "free"},
            # DeFi
            "tax_simulate":    {"category": "defi", "price": 0.01, "tier": "standard"},
            "yield_optimizer": {"category": "defi", "price": 0.01, "tier": "standard"},
            "airdrop_checker": {"category": "defi", "price": 0.005, "tier": "standard"},
            # Meta
            "expose_skills":   {"category": "meta", "price": 0.0, "tier": "free"},
        }

    def get_catalog(self) -> dict:
        """Return full ACP-compatible skill catalog for agent discovery."""
        skills = []
        for tool_name, tool in self._tools.items():
            meta = self._skill_meta.get(tool_name, {"category": "other", "price": 0.0, "tier": "free"})
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
                    "model": "per_call",
                    "currency": "VIRTUAL",
                    "cost": meta["price"],
                    "tier": meta["tier"],
                },
                "endpoint": "/api/acp/execute",
                "method": "POST",
                "version": "2.0.0",
            })

        return {
            "agent": {
                "name": "Crypto Guardian",
                "id": "crypto-guardian-aegis",
                "version": "2.0.0",
                "description": "On-chain AI security agent — scam detection, tx simulation, approval scanning, contract auditing. 21 hireable skills.",
                "capabilities": ["security", "monitoring", "execution", "data", "defi"],
                "chains": ["ethereum", "polygon", "bsc", "arbitrum", "base", "optimism", "avalanche"],
            },
            "protocol": "ACP/OpenClaw",
            "acp_version": "1.0",
            "total_skills": len(skills),
            "skills": skills,
            "stats": {
                "total_calls": self._call_count,
                "uptime": "live",
            },
        }

    async def execute_skill(self, skill_id: str, params: dict) -> dict:
        """Execute a skill by ID with given parameters. Returns tool result."""
        # Extract tool name from skill_id (e.g. "crypto-guardian:scam_check" → "scam_check")
        tool_name = skill_id.split(":")[-1] if ":" in skill_id else skill_id

        tool = self._tools.get(tool_name)
        if not tool:
            return {"status": "error", "message": "Unknown skill: %s" % skill_id,
                    "available": list(self._tools.keys())}

        try:
            self._call_count += 1
            meta = self._skill_meta.get(tool_name, {"price": 0.0})
            self._revenue += meta.get("price", 0.0)

            # Execute the tool
            result = await tool.ainvoke(params)

            # Log the call
            self._call_log.append({
                "skill": tool_name, "params": str(params)[:100],
                "timestamp": time.time(), "success": True,
            })

            # Parse result if it's a JSON string
            try:
                parsed = json.loads(result) if isinstance(result, str) else result
            except (json.JSONDecodeError, TypeError):
                parsed = {"result": result}

            return {
                "status": "success",
                "skill": tool_name,
                "result": parsed,
                "billing": {
                    "charged": meta.get("price", 0.0),
                    "currency": "VIRTUAL",
                },
            }

        except Exception as e:
            self._call_log.append({
                "skill": tool_name, "params": str(params)[:100],
                "timestamp": time.time(), "success": False, "error": str(e),
            })
            return {"status": "error", "skill": tool_name, "message": str(e)}

    def get_manifest(self) -> dict:
        """Static manifest for ACP registry crawlers."""
        return {
            "name": "Crypto Guardian",
            "id": "crypto-guardian-aegis",
            "protocol": "ACP",
            "version": "2.0.0",
            "endpoint": "/api/acp/execute",
            "catalog_url": "/api/acp/catalog",
            "health_url": "/api/health",
            "capabilities": ["security", "monitoring", "execution", "data", "defi"],
            "chains": ["ethereum", "polygon", "bsc", "arbitrum", "base", "optimism", "avalanche"],
            "pricing_model": "per_call",
            "currency": "VIRTUAL",
        }

    def get_stats(self) -> dict:
        """Get ACP service statistics."""
        return {
            "totalCalls": self._call_count,
            "totalRevenue": self._revenue,
            "recentCalls": self._call_log[-10:],
            "skillCount": len(self._tools),
        }
