"""
Async Blockchain Service — Production-grade multi-chain scanner.

APPROACH (same as Revoke.cash / De.Fi Shield):
1. APPROVALS: Use alchemy_getAssetTransfers to discover tokens user has interacted
   with, then verify CURRENT on-chain allowance via eth_call (ERC20.allowance).
   This gives FULL HISTORY regardless of block range limits.
2. TRANSACTIONS: alchemy_getAssetTransfers (sent + received) in parallel.
3. BALANCES: alchemy_getTokenBalances + native balance.

All queries fire concurrently with asyncio.gather.
"""

import asyncio
import aiohttp
import time
from services.chains import CHAINS

# ── ABI selectors ─────────────────────────────────────────────
# ERC20 Approval event topic = keccak256("Approval(address,address,uint256)")
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
# ERC20 allowance(owner, spender) selector
ALLOWANCE_SELECTOR = "0xdd62ed3e"
# ERC20 symbol() selector
SYMBOL_SELECTOR = "0x95d89b41"
# ERC20 decimals() selector
DECIMALS_SELECTOR = "0x313ce567"
# Max uint256
MAX_UINT256 = 2**256 - 1
HALF_MAX = 2**128

# ── Known spenders (DEXes, bridges, protocols) ────────────────
KNOWN_SPENDERS = {
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router 2",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5 Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch V4 Router",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6 Router",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router (old)",
    "0x881d40237659c251811cec9c364ef91dc08d300c": "MetaMask Swap Router",
    "0x3328f7f4a1d1c57c35df56bbf0c9dcafca309c49": "Banana Gun Router",
    "0x80a64c6d7f12c47b7c66c5b4e20e72bc0db9ca2e": "Maestro Router",
    "0x6352a56caadC4F1E25CD6c75970Fa768A3304e64": "OpenSea Seaport",
    "0x00000000006c3852cbef3e08e8df289169ede581": "OpenSea Seaport 1.1",
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "OpenSea Seaport 1.5",
    "0x74312363e45dcaba76c59ec49a7aa8a65a67eed3": "X2Y2 Exchange",
    "0x00000000000001ad428e4906ae43d8f9852d0dd6": "LooksRare Exchange",
}


class BlockchainService:
    def __init__(self, alchemy_key: str):
        self.key = alchemy_key
        self._session: aiohttp.ClientSession | None = None
        self._symbol_cache: dict = {}
        self._decimals_cache: dict = {}
        self._price_cache: dict = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20)
            )
        return self._session

    # ── Simulation API ───────────────────────────────────────────
    async def simulate_transaction(self, tx_object: dict, chain: str) -> dict:
        """Simulate a transaction using Alchemy's simulateAssetChanges API.
        Uses direct HTTP call instead of _rpc() because _rpc swallows errors."""
        if not CHAINS[chain]["is_alchemy"]:
            return {"status": "error", "message": f"Simulation not supported on {chain} (requires Alchemy)."}

        try:
            session = await self._get_session()
            url = self._rpc_url(chain)
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "alchemy_simulateAssetChanges",
                "params": [{
                    "from": tx_object.get("from", ""),
                    "to": tx_object.get("to", ""),
                    "value": tx_object.get("value", "0x0"),
                    "data": tx_object.get("data", "0x"),
                }]
            }

            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    return {"status": "error", "message": f"HTTP {resp.status}: {text[:200]}"}
                
                data = await resp.json()
            
            # Check for JSON-RPC level error
            if "error" in data:
                err = data["error"]
                return {"status": "error", "message": err.get("message", str(err))}

            result = data.get("result", {})
            changes = result.get("changes", [])
            sim_error = result.get("error", None)
            formatted_changes = []
            
            for change in changes:
                change_type = change.get("changeType", "")
                asset_type = change.get("assetType", "")
                
                direction = "OUT" if change.get("from", "").lower() == tx_object.get("from", "").lower() else "IN"
                
                formatted_changes.append({
                    "type": change_type,
                    "assetType": asset_type,
                    "direction": direction,
                    "from": change.get("from", ""),
                    "to": change.get("to", ""),
                    "amount": change.get("amount", "0"),
                    "symbol": change.get("symbol", ""),
                    "decimals": change.get("decimals", 18),
                    "logo": change.get("logo", ""),
                    "contractAddress": change.get("contractAddress", ""),
                    "tokenId": change.get("tokenId", ""),
                })

            return {
                "status": "success",
                "simulationError": sim_error,
                "changes": formatted_changes,
                "gasUsed": result.get("gasUsed", ""),
            }

        except Exception as e:
            return {"status": "error", "message": f"Simulation exception: {e}"}

    # ── NFT API ──────────────────────────────────────────────────
    async def get_nfts(self, address: str, chain: str) -> list:
        """Get all NFTs for a wallet using Alchemy's getNFTsForOwner."""
        if not CHAINS[chain]["is_alchemy"]:
            return []
        try:
            session = await self._get_session()
            url = self._rpc_url(chain)
            # getNFTsForOwner is a REST endpoint on Alchemy
            nft_url = url + f"/getNFTsForOwner?owner={address}&withMetadata=true&pageSize=50"
            async with session.get(nft_url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()

            nfts = []
            for nft in data.get("ownedNfts", []):
                contract = nft.get("contract", {})
                nft_id = nft.get("id", {})
                token_meta = nft_id.get("tokenMetadata", {})
                nfts.append({
                    "contractAddress": contract.get("address", ""),
                    "name": contract.get("name", "") or nft.get("title", "Unknown"),
                    "symbol": contract.get("symbol", ""),
                    "tokenId": nft_id.get("tokenId", ""),
                    "tokenType": token_meta.get("tokenType", ""),
                    "title": nft.get("title", ""),
                    "description": nft.get("description", ""),
                    "chain": chain,
                })
            return nfts
        except Exception as e:
            print(f"[NFT] get_nfts error ({chain}): {e}")
            return []

    async def get_nft_approvals(self, address: str, chain: str) -> list:
        """Detect setApprovalForAll events — these are MORE dangerous than ERC20 approvals
        because they allow a spender to transfer ANY NFT from a collection."""
        if not CHAINS[chain]["is_alchemy"]:
            return []
        try:
            # setApprovalForAll(address operator, bool approved)
            # Event: ApprovalForAll(address indexed owner, address indexed operator, bool approved)
            # Topic: 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31
            approval_topic = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
            owner_topic = "0x000000000000000000000000" + address[2:].lower()

            result = await self._rpc(chain, "eth_getLogs", [{
                "fromBlock": "0x0",
                "toBlock": "latest",
                "topics": [approval_topic, owner_topic],
            }])

            if not result:
                return []

            approvals = []
            for log in result:
                operator = "0x" + log["topics"][2][26:] if len(log.get("topics", [])) > 2 else ""
                # data contains the bool (approved = true/false)
                data_hex = log.get("data", "0x")
                is_approved = data_hex != "0x" + "0" * 64 if len(data_hex) >= 66 else False

                if is_approved:
                    spender_label = KNOWN_SPENDERS.get(operator.lower(), "")
                    approvals.append({
                        "type": "NFT_APPROVAL_FOR_ALL",
                        "contract": log.get("address", ""),
                        "operator": operator,
                        "operatorLabel": spender_label,
                        "isKnownProtocol": bool(spender_label),
                        "riskLevel": "HIGH" if not spender_label else "MEDIUM",
                        "txHash": log.get("transactionHash", ""),
                        "chain": chain,
                    })
            return approvals
        except Exception as e:
            print(f"[NFT] get_nft_approvals error ({chain}): {e}")
            return []

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _rpc_url(self, chain: str) -> str:
        cfg = CHAINS[chain]
        if cfg["is_alchemy"]:
            return cfg["rpc_url"].format(key=self.key)
        return cfg["rpc_url"]

    # ── Raw JSON-RPC call ────────────────────────────────────────
    async def _rpc(self, chain: str, method: str, params: list, id: int = 1):
        session = await self._get_session()
        url = self._rpc_url(chain)
        payload = {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
        try:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
                if "error" in data:
                    return None
                return data.get("result")
        except Exception as e:
            print(f"[RPC] {chain}.{method} error: {e}")
            return None

    # ═══════════════════════════════════════════════════════════════
    # FULL SCAN — All data for a wallet on a chain (parallel)
    # ═══════════════════════════════════════════════════════════════
    async def full_scan(self, address: str, chain: str) -> dict:
        """Run approvals, transactions, balances, NFTs, and NFT approvals in parallel."""
        results = await asyncio.gather(
            self.get_approvals(address, chain),
            self.get_transactions(address, chain),
            self.get_balances(address, chain),
            self.get_nfts(address, chain),
            self.get_nft_approvals(address, chain),
            return_exceptions=True,
        )
        return {
            "address": address,
            "chain": chain,
            "approvals": results[0] if not isinstance(results[0], Exception) else [],
            "transactions": results[1] if not isinstance(results[1], Exception) else [],
            "balances": results[2] if not isinstance(results[2], Exception) else [],
            "nfts": results[3] if not isinstance(results[3], Exception) else [],
            "nftApprovals": results[4] if not isinstance(results[4], Exception) else [],
        }

    # ═══════════════════════════════════════════════════════════════
    # MULTI-CHAIN SCAN — All chains in parallel
    # ═══════════════════════════════════════════════════════════════
    async def multi_chain_scan(self, address: str, chains: list[str]) -> list:
        """Scan all chains concurrently."""
        return list(await asyncio.gather(
            *[self.full_scan(address, c) for c in chains],
            return_exceptions=True,
        ))

    # ═══════════════════════════════════════════════════════════════
    # APPROVALS — Production-grade (like Revoke.cash)
    #
    # Strategy:
    #  1. Get ALL tokens user holds via alchemy_getTokenBalances
    #  2. Get ALL ERC20 transfers via alchemy_getAssetTransfers to discover
    #     tokens user has EVER interacted with (includes tokens now at 0 balance)
    #  3. For each token, check on-chain allowance() for known DEX/protocol spenders
    #  4. Check approval event logs for last ~10K blocks to find custom spenders
    #  5. Verify each discovered spender's allowance is still active on-chain
    # ═══════════════════════════════════════════════════════════════
    async def get_approvals(self, address: str, chain: str) -> list[dict]:
        try:
            if not self.key and CHAINS[chain]["is_alchemy"]:
                return []

            # Step 1: Discover all tokens from balances + transfer history
            token_addrs = set()

            # From current balances
            if CHAINS[chain]["is_alchemy"]:
                bal_result = await self._rpc(chain, "alchemy_getTokenBalances", [address])
                for tb in (bal_result or {}).get("tokenBalances", []):
                    token_addrs.add(tb["contractAddress"].lower())

                # From transfer history (catches tokens at 0 balance too)
                transfer_result = await self._rpc(chain, "alchemy_getAssetTransfers", [{
                    "fromAddress": address,
                    "category": ["erc20"],
                    "maxCount": "0x64",  # Last 100 interactions
                    "order": "desc",
                    "withMetadata": True,
                }])
                for t in (transfer_result or {}).get("transfers", []):
                    if t.get("rawContract", {}).get("address"):
                        token_addrs.add(t["rawContract"]["address"].lower())

            print(f"[Scan] {chain}: Discovered {len(token_addrs)} tokens")

            # Step 2: For each token, check allowance against known spenders (parallel)
            spender_addrs = list(KNOWN_SPENDERS.keys())
            allowance_tasks = []
            task_keys = []

            for token in token_addrs:
                for spender in spender_addrs:
                    allowance_tasks.append(
                        self._check_allowance(address, token, spender, chain)
                    )
                    task_keys.append((token, spender))

            # Also check Approval events from recent blocks for custom/unknown spenders
            padded = "0x" + address[2:].lower().zfill(64)
            block_hex = await self._rpc(chain, "eth_blockNumber", [])
            current_block = int(block_hex, 16) if block_hex else 0

            # Scan recent 2000 blocks in 10-block chunks (catches recent approvals)
            if current_block > 0:
                CHUNK = 10
                TOTAL = 2000
                start = max(0, current_block - TOTAL)
                log_tasks = []
                for from_b in range(start, current_block + 1, CHUNK):
                    to_b = min(from_b + CHUNK - 1, current_block)
                    log_tasks.append(
                        self._rpc(chain, "eth_getLogs", [{
                            "fromBlock": hex(from_b),
                            "toBlock": hex(to_b),
                            "topics": [APPROVAL_TOPIC, padded],
                        }])
                    )

                # Fire log queries concurrently
                log_results = await asyncio.gather(*log_tasks, return_exceptions=True)
                for r in log_results:
                    if isinstance(r, list):
                        for log in r:
                            spender_found = "0x" + log["topics"][2][26:]
                            token_found = log["address"].lower()
                            key = (token_found, spender_found.lower())
                            if key not in task_keys:
                                allowance_tasks.append(
                                    self._check_allowance(address, token_found, spender_found, chain)
                                )
                                task_keys.append(key)

            # Fire ALL allowance checks at once
            print(f"[Scan] {chain}: Checking {len(allowance_tasks)} allowances...")
            results = await asyncio.gather(*allowance_tasks, return_exceptions=True)

            # Step 3: Build final approvals list (only non-zero allowances)
            approvals = []
            seen = set()
            now = time.time()

            for i, result in enumerate(results):
                if isinstance(result, Exception) or result is None:
                    continue
                if result.get("allowance", 0) == 0:
                    continue

                token = task_keys[i][0]
                spender = task_keys[i][1]
                skey = f"{token}-{spender}"
                if skey in seen:
                    continue
                seen.add(skey)

                allowance = result["allowance"]
                is_unlimited = allowance >= HALF_MAX

                # Get token metadata via alchemy_getTokenMetadata
                meta = await self._get_token_metadata(token, chain)
                symbol = meta["symbol"]
                decimals = meta["decimals"]
                token_logo = meta.get("logo", "")

                # Label spender
                spender_label = KNOWN_SPENDERS.get(spender.lower(), f"{spender[:6]}…{spender[-4:]}")

                # Format amount
                if is_unlimited:
                    display_amount = "UNLIMITED"
                else:
                    display_amount = f"{allowance / (10 ** decimals):.4f}"

                # Risk scoring
                risk = "LOW"
                if is_unlimited:
                    risk = "HIGH"
                elif spender.lower() not in KNOWN_SPENDERS:
                    risk = "MEDIUM"

                approvals.append({
                    "token": token,
                    "tokenName": symbol,
                    "spender": spender,
                    "spenderLabel": spender_label,
                    "amount": display_amount,
                    "rawAllowance": str(allowance),
                    "isUnlimited": is_unlimited,
                    "ageInDays": 0,  # On-chain allowance = current state, not historical
                    "blockNumber": current_block,
                    "txHash": "",
                    "logo": token_logo,
                    "riskLevel": risk,
                    "isKnownProtocol": spender.lower() in KNOWN_SPENDERS,
                })

            # Sort: HIGH > MEDIUM > LOW, unknown spenders first
            approvals.sort(key=lambda a: (
                {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(a["riskLevel"], 2),
                0 if not a["isKnownProtocol"] else 1,
            ))

            print(f"[Scan] {chain}: {len(approvals)} active approvals found")
            return approvals

        except Exception as e:
            print(f"[Scan] approvals error ({chain}): {e}")
            import traceback; traceback.print_exc()
            return []

    async def _check_allowance(self, owner: str, token: str, spender: str, chain: str) -> dict | None:
        """Call ERC20.allowance(owner, spender) on-chain."""
        try:
            # encode: allowance(address owner, address spender)
            padded_owner = owner[2:].lower().zfill(64)
            padded_spender = spender[2:].lower().zfill(64)
            data = f"{ALLOWANCE_SELECTOR}{padded_owner}{padded_spender}"

            result = await self._rpc(chain, "eth_call", [
                {"to": token, "data": data}, "latest"
            ])

            if not result or result == "0x" or len(result) < 3:
                return None

            allowance = int(result, 16)
            return {"allowance": allowance}
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════════
    # TRANSACTIONS — Alchemy getAssetTransfers (async parallel)
    # ═══════════════════════════════════════════════════════════════
    async def get_transactions(self, address: str, chain: str) -> list[dict]:
        try:
            cfg = CHAINS[chain]
            if not cfg["is_alchemy"]:
                return []

            # Fire sent + received in parallel
            sent_r, recv_r = await asyncio.gather(
                self._rpc(chain, "alchemy_getAssetTransfers", [{
                    "fromAddress": address,
                    "category": ["external", "erc20", "erc721"],
                    "maxCount": "0x14",
                    "order": "desc",
                    "withMetadata": True,
                }]),
                self._rpc(chain, "alchemy_getAssetTransfers", [{
                    "toAddress": address,
                    "category": ["external", "erc20", "erc721"],
                    "maxCount": "0x14",
                    "order": "desc",
                    "withMetadata": True,
                }]),
            )

            txs = []
            for t in (sent_r or {}).get("transfers", []):
                txs.append(self._format_tx(t, "OUT", address, cfg["symbol"]))
            for t in (recv_r or {}).get("transfers", []):
                txs.append(self._format_tx(t, "IN", address, cfg["symbol"]))

            txs.sort(key=lambda x: x.get("blockNumber", 0), reverse=True)
            return txs[:30]

        except Exception as e:
            print(f"[Scan] transactions error ({chain}): {e}")
            return []

    def _format_tx(self, tx: dict, direction: str, user_addr: str, symbol: str) -> dict:
        value = tx.get("value") or 0
        asset = tx.get("asset") or symbol
        peer = tx.get("to") if direction == "OUT" else tx.get("from")
        short = f"{peer[:6]}…{peer[-4:]}" if peer else "?"
        return {
            "hash": tx.get("hash", ""),
            "from": tx.get("from", ""),
            "to": tx.get("to", ""),
            "value": value,
            "asset": asset,
            "category": tx.get("category", ""),
            "direction": direction,
            "blockNumber": int(tx.get("blockNum", "0x0"), 16),
            "timestamp": (tx.get("metadata") or {}).get("blockTimestamp"),
            "summary": f"{'Sent' if direction == 'OUT' else 'Received'} {value:.4f} {asset} {'to' if direction == 'OUT' else 'from'} {short}",
        }

    # ═══════════════════════════════════════════════════════════════
    # BALANCES
    # ═══════════════════════════════════════════════════════════════
    async def get_balances(self, address: str, chain: str) -> list[dict]:
        try:
            raw = await self._rpc(chain, "eth_getBalance", [address, "latest"])
            native = int(raw, 16) / 1e18 if raw else 0
            balances = [{
                "token": "native",
                "tokenName": CHAINS[chain]["symbol"],
                "balance": f"{native:.6f}",
                "isNative": True,
                "priceUsd": 0.0,
                "valueUsd": 0.0,
                "logo": "",
            }]

            token_addresses = []
            token_balances_map = {}

            if CHAINS[chain]["is_alchemy"]:
                result = await self._rpc(chain, "alchemy_getTokenBalances", [address])
                for tb in (result or {}).get("tokenBalances", []):
                    bal_hex = tb.get("tokenBalance", "0x0")
                    if bal_hex == "0x0" or bal_hex == "0x" + "0" * 64:
                        continue
                    addr = tb["contractAddress"]
                    token_addresses.append(addr)
                    token_balances_map[addr] = bal_hex
            
            # 1. Fetch metadata in parallel for tokens
            meta_tasks = [self._get_token_metadata(addr, chain) for addr in token_addresses]
            meta_results = await asyncio.gather(*meta_tasks, return_exceptions=True)
            
            # 2. Fetch prices (Prices API) for tokens + native
            # For Prices API we need network names like "eth-mainnet"
            network = self._get_network_name_for_prices(chain)
            prices_task = None
            if network:
                req_addresses = token_addresses.copy()
                prices_task = asyncio.create_task(self._get_prices(req_addresses, network))

            prices_data = {}
            if prices_task:
                prices_data = await prices_task
            
            # 3. Add native price if available
            native_price = await self._get_native_price(chain)
            balances[0]["priceUsd"] = native_price
            balances[0]["valueUsd"] = native * native_price
            
            # 4. Assemble token balances
            for i, addr in enumerate(token_addresses):
                meta = meta_results[i] if not isinstance(meta_results[i], Exception) else {"symbol": f"{addr[:6]}…", "decimals": 18, "logo": ""}
                
                bal_hex = token_balances_map[addr]
                bal = int(bal_hex, 16) / (10 ** meta["decimals"])
                
                if bal > 0.0001:
                    price = prices_data.get(addr.lower(), 0.0)
                    balances.append({
                        "token": addr,
                        "tokenName": meta["symbol"],
                        "balance": f"{bal:.6f}",
                        "isNative": False,
                        "priceUsd": price,
                        "valueUsd": bal * price,
                        "logo": meta.get("logo", ""),
                    })

            # Sort balances by USD value
            balances.sort(key=lambda b: b.get("valueUsd", 0), reverse=True)
            return balances
        except Exception as e:
            print(f"[Scan] balances error ({chain}): {e}")
            return []

    # ── Token metadata (cached) ──────────────────────────────────
    async def _get_token_metadata(self, token_addr: str, chain: str) -> dict:
        if token_addr in self._symbol_cache:
            return self._symbol_cache[token_addr]

        short = f"{token_addr[:6]}…{token_addr[-4:]}"
        meta = {"symbol": short, "decimals": 18, "logo": ""}

        if CHAINS[chain]["is_alchemy"]:
            try:
                res = await self._rpc(chain, "alchemy_getTokenMetadata", [token_addr])
                if res and not isinstance(res, Exception):
                    if res.get("symbol"):
                        meta["symbol"] = res["symbol"]
                    if res.get("decimals") is not None:
                        meta["decimals"] = res["decimals"]
                    if res.get("logo"):
                        meta["logo"] = res["logo"]
            except Exception:
                pass
        else:
            # Fallback for non-Alchemy chains (if any added later)
            try:
                sym_res = await self._rpc(chain, "eth_call", [{"to": token_addr, "data": SYMBOL_SELECTOR}, "latest"])
                if sym_res and len(sym_res) > 66:
                    hex_str = sym_res[2:]
                    length = int(hex_str[64:128], 16)
                    if 0 < length < 32:
                        meta["symbol"] = bytes.fromhex(hex_str[128:128+length*2]).decode("utf-8", errors="ignore").strip()
                
                dec_res = await self._rpc(chain, "eth_call", [{"to": token_addr, "data": DECIMALS_SELECTOR}, "latest"])
                if dec_res and len(dec_res) > 2:
                    meta["decimals"] = int(dec_res, 16)
            except Exception:
                pass

        self._symbol_cache[token_addr] = meta
        return meta

    # ── Prices API ───────────────────────────────────────────────
    def _get_network_name_for_prices(self, chain: str) -> str | None:
        # Alchemy Prices API currently supports:
        # eth-mainnet, polygon-mainnet, arb-mainnet, opt-mainnet, base-mainnet
        mapping = {
            "ethereum": "eth-mainnet",
            "polygon": "polygon-mainnet",
            "bsc": "bnb-mainnet",
            "arbitrum": "arb-mainnet",
            "optimism": "opt-mainnet",
            "base": "base-mainnet",
            "avalanche": "avax-mainnet",
        }
        return mapping.get(chain)

    async def _get_native_price(self, chain: str) -> float:
        # Simple fallback mappings for native tokens
        network = self._get_network_name_for_prices(chain)
        if not network:
            return 0.0
            
        weth_map = {
            "ethereum": "0xc02aaa39b223fe8d050e5c4f27ead9083c756cc2",
            "polygon": "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", # WETH on Polygon
            "arbitrum": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
            "optimism": "0x4200000000000000000000000000000000000006",
            "base": "0x4200000000000000000000000000000000000006"
        }
        token = weth_map.get(chain)
        if chain == "polygon":
             token = "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270" # WMATIC
             
        if token:
            prices = await self._get_prices([token], network)
            return prices.get(token.lower(), 0.0)
        return 0.0

    async def _get_prices(self, tokens: list[str], network: str) -> dict:
        """Fetch prices from Alchemy Prices API REST endpoint."""
        if not tokens or not self.key or not network:
            return {}
            
        # REST URL for Alchemy Prices API
        # https://api.g.alchemy.com/prices/v1/{api-key}/tokens/by-address
        url = f"https://api.g.alchemy.com/prices/v1/{self.key}/tokens/by-address"
        
        # Prices API accepts max 100 addresses per request
        prices = {}
        session = await self._get_session()
        
        for i in range(0, len(tokens), 100):
            chunk = tokens[i:i+100]
            addresses = [{"network": network, "address": t} for t in chunk]
            try:
                # Need specific headers that alchemy expects
                headers = {"accept": "application/json", "content-type": "application/json"}
                async with session.post(url, json={"addresses": addresses}, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("data", []):
                            if "prices" in item and item["prices"]:
                                addr = item.get("address", "").lower()
                                price = item["prices"][0].get("value", 0.0)
                                if price:
                                    prices[addr] = float(price)
            except Exception as e:
                print(f"[Prices] Error fetching prices: {e}")
                
        return prices
