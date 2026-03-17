"""
Crypto Guardian - Cross-Chain Bridge Safety (Li.Fi API)
Uses Li.Fi API (https://li.quest/v1) - no API key required.
Finds best bridge routes, compares options, returns safety info.
"""

import aiohttp

LIFI_BASE = "https://li.quest/v1"

# Chain IDs (EVM standard)
CHAIN_IDS = {
    "ethereum": 1,
    "polygon": 137,
    "bsc": 56,
    "arbitrum": 42161,
    "base": 8453,
    "optimism": 10,
    "avalanche": 43114,
}

# Native token addresses (Li.Fi uses 0x0 or specific for native)
NATIVE_TOKENS = {
    "ethereum": "0x0000000000000000000000000000000000000000",
    "polygon": "0x0000000000000000000000000000000000000000",
    "bsc": "0x0000000000000000000000000000000000000000",
    "arbitrum": "0x0000000000000000000000000000000000000000",
    "base": "0x0000000000000000000000000000000000000000",
    "optimism": "0x0000000000000000000000000000000000000000",
    "avalanche": "0x0000000000000000000000000000000000000000",
}

# Common tokens (for "ETH", "USDC" etc. resolution)
COMMON_TOKENS = {
    "ETH": {
        1: "0x0000000000000000000000000000000000000000",
        42161: "0x0000000000000000000000000000000000000000",
        8453: "0x0000000000000000000000000000000000000000",
        10: "0x0000000000000000000000000000000000000000",
    },
    "USDC": {
        1: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        137: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
        42161: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        10: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
        43114: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
    },
    "USDT": {
        1: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        137: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
        56: "0x55d398326f99059fF775485246999027B3197955",
        42161: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
        43114: "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7",
    },
}


class BridgeService:
    """Cross-chain bridge route finder using Li.Fi API."""

    def __init__(self):
        self._session = None

    async def _get_session(self):
        if not self._session or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    def _resolve_chain_id(self, chain_name):
        """Convert chain name to EVM chain ID."""
        return CHAIN_IDS.get(chain_name.lower())

    def _resolve_token(self, token_symbol, chain_id):
        """Resolve a token symbol to its address on a specific chain."""
        symbol = token_symbol.upper()
        if symbol in COMMON_TOKENS and chain_id in COMMON_TOKENS[symbol]:
            return COMMON_TOKENS[symbol][chain_id]
        # Default to native token
        return "0x0000000000000000000000000000000000000000"

    async def find_route(self, from_chain, to_chain, token="ETH", amount_human=1.0, from_address=None):
        """Find the best bridge route using Li.Fi /quote endpoint.
        
        Args:
            from_chain: source chain name (e.g., "ethereum")
            to_chain: destination chain name (e.g., "base")
            token: token symbol (e.g., "ETH", "USDC")
            amount_human: amount in human-readable format (e.g., 1.0 for 1 ETH)
            from_address: user's wallet address (optional)
        """
        from_chain_id = self._resolve_chain_id(from_chain)
        to_chain_id = self._resolve_chain_id(to_chain)

        if not from_chain_id or not to_chain_id:
            return {"error": "Unsupported chain. Supported: %s" % ", ".join(CHAIN_IDS.keys())}

        from_token = self._resolve_token(token, from_chain_id)
        to_token = self._resolve_token(token, to_chain_id)

        # Convert to wei (18 decimals for most, 6 for USDC/USDT)
        decimals = 6 if token.upper() in ("USDC", "USDT") else 18
        amount_wei = str(int(amount_human * (10 ** decimals)))

        # Default from_address if not provided
        if not from_address:
            from_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # Dummy for quote

        params = {
            "fromChain": str(from_chain_id),
            "toChain": str(to_chain_id),
            "fromToken": from_token,
            "toToken": to_token,
            "fromAmount": amount_wei,
            "fromAddress": from_address,
        }

        try:
            session = await self._get_session()
            async with session.get("%s/quote" % LIFI_BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    return {"error": "Li.Fi API error (%d): %s" % (resp.status, error_text[:200])}

                data = await resp.json()

                # Parse the response
                estimate = data.get("estimate", {})
                action = data.get("action", {})
                tool_details = data.get("toolDetails", {})

                to_amount_raw = estimate.get("toAmount", "0")
                to_amount = int(to_amount_raw) / (10 ** decimals) if to_amount_raw else 0

                gas_costs = estimate.get("gasCosts", [])
                total_gas_usd = sum(float(g.get("amountUSD", 0)) for g in gas_costs)

                fee_costs = estimate.get("feeCosts", [])
                total_fee_usd = sum(float(f.get("amountUSD", 0)) for f in fee_costs)

                execution_duration = estimate.get("executionDuration", 0)

                return {
                    "route": {
                        "from": {"chain": from_chain, "token": token, "amount": amount_human},
                        "to": {"chain": to_chain, "token": token, "amount": round(to_amount, 6)},
                        "bridge": tool_details.get("name", "Unknown"),
                        "estimatedTime": "%d seconds" % execution_duration if execution_duration else "Unknown",
                        "gasCostUsd": round(total_gas_usd, 4),
                        "bridgeFeeUsd": round(total_fee_usd, 4),
                        "totalCostUsd": round(total_gas_usd + total_fee_usd, 4),
                    },
                    "rawQuote": data,
                }
        except aiohttp.ClientError as e:
            return {"error": "Network error: %s" % str(e)}
        except Exception as e:
            return {"error": "Error: %s" % str(e)}

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
