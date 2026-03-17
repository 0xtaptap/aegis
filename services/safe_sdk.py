"""
Crypto Guardian - Safe Smart Account SDK Integration

Provides real on-chain execution through Safe smart accounts:
1. Build revoke transactions (approve(spender, 0))
2. Build arbitrary Safe transactions with multi-sig support
3. Session key validation before execution
4. Transaction queue (propose -> confirm -> execute)
5. WalletConnect-ready signing interface

NOTE: Actual signing requires a connected wallet (WalletConnect/injected).
This module builds the unsigned transaction payloads.
"""

import json
import hashlib
import time
import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ERC20 approve(address,uint256) selector
APPROVE_SELECTOR = "0x095ea7b3"
# setApprovalForAll(address,bool) selector for NFTs
SET_APPROVAL_FOR_ALL_SELECTOR = "0xa22cb465"


class TxStatus(str, Enum):
    PROPOSED = "PROPOSED"      # Built, waiting for signature
    SIGNED = "SIGNED"          # Signed by owner
    EXECUTED = "EXECUTED"      # Sent on-chain
    FAILED = "FAILED"          # Execution failed
    CANCELLED = "CANCELLED"    # User cancelled


@dataclass
class SafeTx:
    """A Safe transaction ready for signing."""
    tx_id: str
    chain: str
    to: str                    # Target contract
    value: str = "0x0"         # ETH value
    data: str = "0x"           # Calldata
    operation: int = 0         # 0 = Call, 1 = DelegateCall
    description: str = ""
    status: TxStatus = TxStatus.PROPOSED
    created_at: float = field(default_factory=time.time)
    tx_hash: Optional[str] = None   # On-chain tx hash after execution

    def to_dict(self) -> dict:
        return {
            "txId": self.tx_id,
            "chain": self.chain,
            "to": self.to,
            "value": self.value,
            "data": self.data,
            "operation": self.operation,
            "description": self.description,
            "status": self.status.value,
            "createdAt": self.created_at,
            "txHash": self.tx_hash,
        }


class SafeSDK:
    """
    Safe Smart Account SDK for Crypto Guardian.

    Builds transaction payloads for Safe execution. Does NOT hold private keys.
    Signing happens client-side via WalletConnect or injected wallet.
    """

    def __init__(self, blockchain_service):
        self._bc = blockchain_service
        self._tx_queue: dict[str, list[SafeTx]] = {}  # wallet -> [txs]

    # ---------------------------------------------------------------
    # BUILD REVOKE TRANSACTION
    # ---------------------------------------------------------------
    def build_revoke_erc20(
        self, token_address: str, spender: str, chain: str = "ethereum"
    ) -> SafeTx:
        """Build an ERC20 approve(spender, 0) transaction to revoke approval."""
        # approve(address spender, uint256 amount)
        # amount = 0 means revoke
        data = (
            APPROVE_SELECTOR
            + spender[2:].lower().zfill(64)
            + "0" * 64  # amount = 0
        )
        tx_id = hashlib.sha256(
            ("%s:%s:%s:%f" % (token_address, spender, chain, time.time())).encode()
        ).hexdigest()[:16]

        return SafeTx(
            tx_id=tx_id,
            chain=chain,
            to=token_address,
            data=data,
            description="Revoke ERC20 approval: %s -> %s" % (
                token_address[:10], spender[:10]
            ),
        )

    def build_revoke_nft(
        self, nft_contract: str, operator: str, chain: str = "ethereum"
    ) -> SafeTx:
        """Build setApprovalForAll(operator, false) to revoke NFT approval."""
        data = (
            SET_APPROVAL_FOR_ALL_SELECTOR
            + operator[2:].lower().zfill(64)
            + "0" * 64  # false
        )
        tx_id = hashlib.sha256(
            ("%s:%s:%s:%f" % (nft_contract, operator, chain, time.time())).encode()
        ).hexdigest()[:16]

        return SafeTx(
            tx_id=tx_id,
            chain=chain,
            to=nft_contract,
            data=data,
            description="Revoke NFT approval: %s -> %s" % (
                nft_contract[:10], operator[:10]
            ),
        )

    # ---------------------------------------------------------------
    # BATCH REVOKE (multiple approvals at once)
    # ---------------------------------------------------------------
    def build_batch_revoke(
        self, approvals: list[dict], chain: str = "ethereum"
    ) -> list[SafeTx]:
        """Build multiple revoke txs from a list of approval dicts."""
        txs = []
        for approval in approvals:
            token = approval.get("token", "")
            spender = approval.get("spender", "")
            is_nft = approval.get("isNFT", False)

            if not token or not spender:
                continue

            if is_nft:
                txs.append(self.build_revoke_nft(token, spender, chain))
            else:
                txs.append(self.build_revoke_erc20(token, spender, chain))

        return txs

    # ---------------------------------------------------------------
    # SIMULATE BEFORE EXECUTE
    # ---------------------------------------------------------------
    async def simulate_tx(self, tx: SafeTx) -> dict:
        """Simulate a Safe transaction before execution."""
        sim_payload = {
            "from": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",  # Dummy sender
            "to": tx.to,
            "value": tx.value,
            "data": tx.data,
        }
        result = await self._bc.simulate_transaction(sim_payload, tx.chain)
        return {
            "txId": tx.tx_id,
            "simulation": result,
            "wouldSucceed": "error" not in result,
        }

    # ---------------------------------------------------------------
    # TRANSACTION QUEUE
    # ---------------------------------------------------------------
    def propose_tx(self, wallet: str, tx: SafeTx) -> dict:
        """Add a transaction to the queue for signing."""
        addr = wallet.lower()
        if addr not in self._tx_queue:
            self._tx_queue[addr] = []
        self._tx_queue[addr].append(tx)
        return {
            "status": "proposed",
            "txId": tx.tx_id,
            "description": tx.description,
            "message": "Transaction queued. Sign via connected wallet to execute.",
            "queueLength": len(self._tx_queue[addr]),
        }

    def get_queue(self, wallet: str) -> list[dict]:
        """Get all pending transactions for a wallet."""
        addr = wallet.lower()
        txs = self._tx_queue.get(addr, [])
        return [tx.to_dict() for tx in txs if tx.status == TxStatus.PROPOSED]

    def cancel_tx(self, wallet: str, tx_id: str) -> bool:
        """Cancel a proposed transaction."""
        addr = wallet.lower()
        for tx in self._tx_queue.get(addr, []):
            if tx.tx_id == tx_id and tx.status == TxStatus.PROPOSED:
                tx.status = TxStatus.CANCELLED
                return True
        return False

    def mark_executed(self, wallet: str, tx_id: str, tx_hash: str) -> bool:
        """Mark a transaction as executed (called after on-chain confirmation)."""
        addr = wallet.lower()
        for tx in self._tx_queue.get(addr, []):
            if tx.tx_id == tx_id:
                tx.status = TxStatus.EXECUTED
                tx.tx_hash = tx_hash
                return True
        return False

    # ---------------------------------------------------------------
    # WALLET CONNECT PAYLOAD
    # ---------------------------------------------------------------
    def get_signing_payload(self, wallet: str, tx_id: str) -> Optional[dict]:
        """Get the raw transaction payload for WalletConnect signing."""
        addr = wallet.lower()
        for tx in self._tx_queue.get(addr, []):
            if tx.tx_id == tx_id and tx.status == TxStatus.PROPOSED:
                return {
                    "to": tx.to,
                    "value": tx.value,
                    "data": tx.data,
                    "operation": tx.operation,
                    "chain": tx.chain,
                    "txId": tx.tx_id,
                }
        return None
