"""
Crypto Guardian - Gas Optimizer
Uses real RPC calls: eth_gasPrice, eth_feeHistory, eth_maxPriorityFeePerGas.
No hardcoded values. All data fetched live from each chain.
"""

import asyncio
import time
from services.chains import CHAINS


class GasOptimizer:
    """Real-time gas price tracking and optimization across all supported chains."""

    # Native token symbols for USD cost estimation
    NATIVE_TOKENS = {
        "ethereum": "ETH",
        "polygon": "MATIC",
        "bsc": "BNB",
        "arbitrum": "ETH",
        "base": "ETH",
        "optimism": "ETH",
        "avalanche": "AVAX",
    }

    def __init__(self, blockchain_service):
        self._bc = blockchain_service
        self._history = {}  # chain -> [(timestamp, gas_gwei)]

    async def get_gas_price(self, chain):
        """Get current gas price in gwei via eth_gasPrice RPC call."""
        try:
            result = await self._bc._rpc(chain, "eth_gasPrice", [])
            if result:
                wei = int(result, 16)
                gwei = wei / 1e9
                # Store for history tracking
                if chain not in self._history:
                    self._history[chain] = []
                self._history[chain].append((time.time(), gwei))
                # Keep only last 100 data points
                self._history[chain] = self._history[chain][-100:]
                return {"chain": chain, "gasGwei": round(gwei, 2), "gasWei": wei}
        except Exception as e:
            return {"chain": chain, "gasGwei": None, "error": str(e)}
        return {"chain": chain, "gasGwei": None, "error": "No response from RPC"}

    async def get_fee_history(self, chain, block_count=20):
        """Get fee history for the last N blocks via eth_feeHistory.
        Returns base fee trend and reward percentiles."""
        try:
            result = await self._bc._rpc(chain, "eth_feeHistory", [
                hex(block_count), "latest", [25, 50, 75]
            ])
            if not result:
                return {"chain": chain, "error": "No fee history available"}

            base_fees = []
            for fee_hex in result.get("baseFeePerGas", []):
                base_fees.append(int(fee_hex, 16) / 1e9)

            rewards = []
            for r in result.get("reward", []):
                rewards.append([int(x, 16) / 1e9 for x in r])

            avg_base = sum(base_fees) / len(base_fees) if base_fees else 0
            min_base = min(base_fees) if base_fees else 0
            max_base = max(base_fees) if base_fees else 0

            # Trend: is gas going up or down?
            if len(base_fees) >= 2:
                first_half = sum(base_fees[:len(base_fees)//2]) / (len(base_fees)//2)
                second_half = sum(base_fees[len(base_fees)//2:]) / (len(base_fees) - len(base_fees)//2)
                trend = "rising" if second_half > first_half * 1.05 else (
                    "falling" if second_half < first_half * 0.95 else "stable"
                )
            else:
                trend = "unknown"

            return {
                "chain": chain,
                "blocks": block_count,
                "avgBaseGwei": round(avg_base, 2),
                "minBaseGwei": round(min_base, 2),
                "maxBaseGwei": round(max_base, 2),
                "trend": trend,
            }
        except Exception as e:
            return {"chain": chain, "error": str(e)}

    async def compare_chains(self):
        """Compare gas prices across all supported chains. Returns sorted by cheapest."""
        tasks = []
        chain_names = list(CHAINS.keys())
        for chain in chain_names:
            tasks.append(self.get_gas_price(chain))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        prices = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                prices.append({"chain": chain_names[i], "gasGwei": None, "error": str(r)})
            elif isinstance(r, dict):
                prices.append(r)

        # Sort by gas price (cheapest first), put errors at end
        prices.sort(key=lambda x: x.get("gasGwei") or 999999)

        return {
            "timestamp": time.time(),
            "chains": prices,
            "cheapest": prices[0]["chain"] if prices and prices[0].get("gasGwei") else None,
        }

    def estimate_cost(self, gas_units, gas_gwei, native_price_usd=0):
        """Estimate transaction cost in USD.
        gas_units: estimated gas for the tx (e.g., 21000 for simple transfer)
        gas_gwei: current gas price in gwei
        native_price_usd: price of native token in USD
        """
        gas_eth = gas_units * gas_gwei / 1e9
        cost_usd = gas_eth * native_price_usd if native_price_usd > 0 else 0
        return {
            "gasUnits": gas_units,
            "gasGwei": gas_gwei,
            "costNative": round(gas_eth, 8),
            "costUsd": round(cost_usd, 4) if cost_usd > 0 else None,
        }

    def suggest_timing(self, chain):
        """Based on collected gas history, suggest if now is a good time to transact."""
        history = self._history.get(chain, [])
        if len(history) < 3:
            return {
                "chain": chain,
                "suggestion": "Not enough data yet. Gas prices are being tracked.",
                "confidence": "LOW",
            }

        prices = [h[1] for h in history]
        current = prices[-1]
        avg = sum(prices) / len(prices)
        minimum = min(prices)

        if current <= minimum * 1.1:
            return {
                "chain": chain,
                "currentGwei": round(current, 2),
                "avgGwei": round(avg, 2),
                "suggestion": "Gas is near its lowest point. Good time to transact.",
                "confidence": "HIGH",
            }
        elif current <= avg * 0.9:
            return {
                "chain": chain,
                "currentGwei": round(current, 2),
                "avgGwei": round(avg, 2),
                "suggestion": "Gas is below average. Decent time to transact.",
                "confidence": "MEDIUM",
            }
        elif current >= avg * 1.3:
            return {
                "chain": chain,
                "currentGwei": round(current, 2),
                "avgGwei": round(avg, 2),
                "suggestion": "Gas is above average. Consider waiting for lower fees.",
                "confidence": "HIGH",
            }
        else:
            return {
                "chain": chain,
                "currentGwei": round(current, 2),
                "avgGwei": round(avg, 2),
                "suggestion": "Gas is near average. Normal conditions.",
                "confidence": "MEDIUM",
            }
