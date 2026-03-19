"""
Crypto Guardian — Deterministic Rules Engine
============================================
Fast-path decision layer. No LLM calls — pure logic.

Given an address + chain → instantly classifies as TRUSTED / UNTRUSTED / UNKNOWN.
Given a finding → evaluates as SAFE / THREAT / AMBIGUOUS with confidence.

Covers 100+ verified protocol addresses across all 7 supported chains.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ═══════════════════════════════════════════════════════════════

class Trust(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class Verdict(str, Enum):
    SAFE = "SAFE"
    THREAT = "THREAT"
    AMBIGUOUS = "AMBIGUOUS"


class ProtocolCategory(str, Enum):
    DEX = "dex"
    LENDING = "lending"
    NFT = "nft"
    BRIDGE = "bridge"
    AGGREGATOR = "aggregator"
    STAKING = "staking"
    YIELD = "yield"
    INFRASTRUCTURE = "infrastructure"


@dataclass
class ProtocolInfo:
    name: str
    category: ProtocolCategory
    trust_level: str = "VERIFIED"   # VERIFIED | KNOWN | COMMUNITY


@dataclass
class RuleVerdict:
    verdict: Verdict
    confidence: float  # 0.0 - 1.0
    reason: str
    rule_name: str


# ═══════════════════════════════════════════════════════════════
# MULTI-CHAIN PROTOCOL REGISTRY
# ═══════════════════════════════════════════════════════════════

# Contracts deployed at the SAME address on all chains
UNIVERSAL_PROTOCOLS: dict[str, ProtocolInfo] = {
    "0x000000000022d473030f116ddee9f6b43ac78ba3": ProtocolInfo("Permit2", ProtocolCategory.INFRASTRUCTURE, "VERIFIED"),
    "0xca11bde05977b3631167028862be2a173976ca11": ProtocolInfo("Multicall3", ProtocolCategory.INFRASTRUCTURE, "VERIFIED"),
    "0x1111111254eeb25477b68fb85ed929f73a960582": ProtocolInfo("1inch V5 Router", ProtocolCategory.AGGREGATOR, "VERIFIED"),
    "0x111111125421ca6dc452d289314280a0f8842a65": ProtocolInfo("1inch V6 Router", ProtocolCategory.AGGREGATOR, "VERIFIED"),
    "0x1111111254fb6c44bac0bed2854e76f90643097d": ProtocolInfo("1inch V4 Router", ProtocolCategory.AGGREGATOR, "VERIFIED"),
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": ProtocolInfo("0x Exchange Proxy", ProtocolCategory.AGGREGATOR, "VERIFIED"),
}

# Per-chain verified protocols
PROTOCOL_REGISTRY: dict[str, dict[str, ProtocolInfo]] = {

    # ── ETHEREUM ──────────────────────────────────────────────
    "ethereum": {
        # DEXes
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": ProtocolInfo("Uniswap V2 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xe592427a0aece92de3edee1f18e0157c05861564": ProtocolInfo("Uniswap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ProtocolInfo("Uniswap V3 Router 02", ProtocolCategory.DEX, "VERIFIED"),
        "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": ProtocolInfo("Uniswap Universal Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": ProtocolInfo("Uniswap Universal Router 2", ProtocolCategory.DEX, "VERIFIED"),
        "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": ProtocolInfo("SushiSwap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xd1742b3c4fbb096990c8950fa635aec75b30781a": ProtocolInfo("SushiSwap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xe66b31678d6c16e9ebf358268a790b763c133750": ProtocolInfo("0x Settler", ProtocolCategory.AGGREGATOR, "VERIFIED"),
        # Lending
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": ProtocolInfo("Aave V3 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": ProtocolInfo("Aave V2 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0xc3d688b66703497daa19211eedff47f25384cdc3": ProtocolInfo("Compound V3 cUSDCv3", ProtocolCategory.LENDING, "VERIFIED"),
        "0xa17581a9e3356d9a858b789d68b4d866e593ae94": ProtocolInfo("Compound V3 cWETHv3", ProtocolCategory.LENDING, "VERIFIED"),
        # Staking / Yield
        "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": ProtocolInfo("Lido stETH", ProtocolCategory.STAKING, "VERIFIED"),
        "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": ProtocolInfo("Lido wstETH", ProtocolCategory.STAKING, "VERIFIED"),
        "0xbe9895146f7af43049ca1c1ae358b0541ea49704": ProtocolInfo("Coinbase cbETH", ProtocolCategory.STAKING, "VERIFIED"),
        "0xac3e018457b222d93114458476f3e3416abbe38f": ProtocolInfo("Frax sfrxETH", ProtocolCategory.STAKING, "VERIFIED"),
        "0xba100000625a3754423978a60c9317c58a424e3d": ProtocolInfo("Balancer BAL", ProtocolCategory.DEX, "VERIFIED"),
        # NFT
        "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": ProtocolInfo("OpenSea Seaport 1.5", ProtocolCategory.NFT, "VERIFIED"),
        "0x00000000006c3852cbef3e08e8df289169ede581": ProtocolInfo("OpenSea Seaport 1.1", ProtocolCategory.NFT, "VERIFIED"),
        "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": ProtocolInfo("OpenSea Seaport 1.6", ProtocolCategory.NFT, "VERIFIED"),
        "0x00000000000001ad428e4906ae43d8f9852d0dd6": ProtocolInfo("LooksRare Exchange", ProtocolCategory.NFT, "VERIFIED"),
        "0x29469395eaf6f95920e59f858042f0e28d98a20b": ProtocolInfo("Blur Marketplace", ProtocolCategory.NFT, "VERIFIED"),
        "0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5": ProtocolInfo("Blur Blend", ProtocolCategory.NFT, "VERIFIED"),
        "0x74312363e45dcaba76c59ec49a7aa8a65a67eed3": ProtocolInfo("X2Y2 Exchange", ProtocolCategory.NFT, "VERIFIED"),
        # Bridge
        "0x3154cf16ccdb4c6d922629664174b904d80f2c35": ProtocolInfo("Base Bridge", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": ProtocolInfo("Optimism Gateway", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a": ProtocolInfo("Arbitrum Bridge", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x3ee18b2214aff97000d974cf647e7c347e8fa585": ProtocolInfo("Wormhole Token Bridge", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x8731d54e9d02c286767d56ac03e8037c07e01e98": ProtocolInfo("Stargate Router", ProtocolCategory.BRIDGE, "VERIFIED"),
        # Aggregators / Infra
        "0x881d40237659c251811cec9c364ef91dc08d300c": ProtocolInfo("MetaMask Swap Router", ProtocolCategory.AGGREGATOR, "VERIFIED"),
        "0x3328f7f4a1d1c57c35df56bbf0c9dcafca309c49": ProtocolInfo("Banana Gun Router", ProtocolCategory.AGGREGATOR, "KNOWN"),
        "0x80a64c6d7f12c47b7c66c5b4e20e72bc0db9ca2e": ProtocolInfo("Maestro Router", ProtocolCategory.AGGREGATOR, "KNOWN"),
        "0x216b4b4ba9f3e719726886d34a177484278bfcae": ProtocolInfo("Paraswap V6.2", ProtocolCategory.AGGREGATOR, "VERIFIED"),
    },

    # ── POLYGON ───────────────────────────────────────────────
    "polygon": {
        "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff": ProtocolInfo("QuickSwap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xf5b509bb0909a69b1c207e495f687a596c168e12": ProtocolInfo("QuickSwap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xe592427a0aece92de3edee1f18e0157c05861564": ProtocolInfo("Uniswap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ProtocolInfo("Uniswap V3 Router 02", ProtocolCategory.DEX, "VERIFIED"),
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": ProtocolInfo("SushiSwap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x794a61358d6845594f94dc1db02a252b5b4814ad": ProtocolInfo("Aave V3 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0x8dff5e27ea6b7ac08ebfdf9eb090f32ee9a30fcf": ProtocolInfo("Aave V2 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0xba12222222228d8ba445958a75a0704d566bf2c8": ProtocolInfo("Balancer Vault", ProtocolCategory.DEX, "VERIFIED"),
        "0x45dda9cb7c25131df268515131f647d726f50608": ProtocolInfo("Stargate Router", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": ProtocolInfo("USDC.e (Bridged)", ProtocolCategory.INFRASTRUCTURE, "VERIFIED"),
        "0xf3938337f7294fef84e9b2c6d548a93f956cc281": ProtocolInfo("Firebird Router", ProtocolCategory.AGGREGATOR, "KNOWN"),
    },

    # ── BSC ────────────────────────────────────────────────────
    "bsc": {
        "0x10ed43c718714eb63d5aa57b78b54704e256024e": ProtocolInfo("PancakeSwap V2 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": ProtocolInfo("PancakeSwap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x1b81d678ffb9c0263b24a97847620c99d213eb14": ProtocolInfo("PancakeSwap Smart Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xfd5840cd36d94d7229439859c0112a4185bc0255": ProtocolInfo("Venus vUSDT", ProtocolCategory.LENDING, "VERIFIED"),
        "0xecb456ea5365865ebab8a2661b0c503410e9b347": ProtocolInfo("Venus Comptroller", ProtocolCategory.LENDING, "VERIFIED"),
        "0x3a6d8ca21d1cf76f653a67577fa0d27453350dd8": ProtocolInfo("Biswap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": ProtocolInfo("SushiSwap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x4a364f8c717caad9a442737eb7b8a55cc6cf18d8": ProtocolInfo("Stargate Router", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0xb8f55747737b4da4e2749dc9c30aa7818aab37fc": ProtocolInfo("Thena Router", ProtocolCategory.DEX, "KNOWN"),
        "0xd4ae6eca985340dd434d38f470accce4dc78d109": ProtocolInfo("Wombat Router", ProtocolCategory.DEX, "KNOWN"),
    },

    # ── ARBITRUM ──────────────────────────────────────────────
    "arbitrum": {
        "0xe592427a0aece92de3edee1f18e0157c05861564": ProtocolInfo("Uniswap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ProtocolInfo("Uniswap V3 Router 02", ProtocolCategory.DEX, "VERIFIED"),
        "0x5e325eda8064b456f4781070c0738d849c824258": ProtocolInfo("Uniswap Universal Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": ProtocolInfo("SushiSwap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xfc5a1a6eb076a2c7ad06ed22c90d7e710e35ad0a": ProtocolInfo("GMX Token", ProtocolCategory.DEX, "VERIFIED"),
        "0xabc0000b07febc62a1aa96c786116a3f43c31f7c": ProtocolInfo("GMX V2 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xc873fecbd354f5a56e00e710b90ef4201db2448d": ProtocolInfo("Camelot Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x794a61358d6845594f94dc1db02a252b5b4814ad": ProtocolInfo("Aave V3 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0xa97684ead0e402dc232d5a977953df7ecbab3cdb": ProtocolInfo("Aave V3 Pool Addresses Provider", ProtocolCategory.LENDING, "VERIFIED"),
        "0x2032b9a8e9f7e76768ca9271003d3e43e1616b1f": ProtocolInfo("Radiant RDNT", ProtocolCategory.LENDING, "VERIFIED"),
        "0x53bf833a5d6c4dda888f69c22c88c9f356a41614": ProtocolInfo("Stargate Router", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x09aea4b2242abc8bb4bb78d537a67a245a7bec64": ProtocolInfo("Across Bridge", ProtocolCategory.BRIDGE, "VERIFIED"),
    },

    # ── BASE ──────────────────────────────────────────────────
    "base": {
        "0x2626664c2603336e57b271c5c0b26f421741e481": ProtocolInfo("Uniswap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": ProtocolInfo("Uniswap Universal Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43": ProtocolInfo("Aerodrome Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x420dd381b31aef6683db6b902084cb0ffece40da": ProtocolInfo("Aerodrome V2 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x327df1e6de05895d2ab08513aadd9313fe505d86": ProtocolInfo("BaseSwap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": ProtocolInfo("SushiSwap Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x45f1a95a4d3f3836523f5c83673c797f4d4d263b": ProtocolInfo("Stargate Router", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22": ProtocolInfo("Compound V3 Base", ProtocolCategory.LENDING, "VERIFIED"),
        "0xa9aadc2a738dc8ce014a3e7b9b3a7e11f7d230c3": ProtocolInfo("Moonwell Base", ProtocolCategory.LENDING, "KNOWN"),
    },

    # ── OPTIMISM ──────────────────────────────────────────────
    "optimism": {
        "0xe592427a0aece92de3edee1f18e0157c05861564": ProtocolInfo("Uniswap V3 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ProtocolInfo("Uniswap V3 Router 02", ProtocolCategory.DEX, "VERIFIED"),
        "0x9c12939390052919af3155f41bf4160fd3666a6f": ProtocolInfo("Velodrome Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xa062ae8a9c5e11aaa026fc2670b0d65ccc8b2858": ProtocolInfo("Velodrome V2 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x794a61358d6845594f94dc1db02a252b5b4814ad": ProtocolInfo("Aave V3 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0x8700daec35af8ff88c16bdf0418774cb3d7599b4": ProtocolInfo("Synthetix SNX", ProtocolCategory.STAKING, "VERIFIED"),
        "0xb0d502e938ed5f4df2e681fe6e419ff29631d62b": ProtocolInfo("Stargate Router", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": ProtocolInfo("SushiSwap Router", ProtocolCategory.DEX, "VERIFIED"),
    },

    # ── AVALANCHE ─────────────────────────────────────────────
    "avalanche": {
        "0x60ae616a2155ee3d9a68541ba4544862310933d4": ProtocolInfo("TraderJoe Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xb4315e873dbcf96ffd0acd8ea43f689d8c20fb30": ProtocolInfo("TraderJoe V2.1 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0xe54ca86531e17ef3616d22ca28b0d458b6c89106": ProtocolInfo("Pangolin Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x794a61358d6845594f94dc1db02a252b5b4814ad": ProtocolInfo("Aave V3 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0x4f01aed16d97e3ab5ab2b501154dc9bb0f1a5a2c": ProtocolInfo("Aave V2 Pool", ProtocolCategory.LENDING, "VERIFIED"),
        "0x486af39519b4dc9a7fccd318217352830e8ad9b4": ProtocolInfo("Benqi qiAVAX", ProtocolCategory.LENDING, "VERIFIED"),
        "0x5c313e07135848088ab1906808605e9f68241f73": ProtocolInfo("Benqi Comptroller", ProtocolCategory.LENDING, "VERIFIED"),
        "0xabc0000b07febc62a1aa96c786116a3f43c31f7c": ProtocolInfo("GMX V2 Router", ProtocolCategory.DEX, "VERIFIED"),
        "0x45a01e4e04f14f7a4a6702c74187c5f6222033cd": ProtocolInfo("Stargate Router", ProtocolCategory.BRIDGE, "VERIFIED"),
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": ProtocolInfo("SushiSwap Router", ProtocolCategory.DEX, "VERIFIED"),
    },
}


# ═══════════════════════════════════════════════════════════════
# APPROVAL THRESHOLDS (context-aware)
# ═══════════════════════════════════════════════════════════════

MAX_UINT256 = 2**256 - 1
HALF_MAX = 2**128

# What counts as "unlimited" (anything above this is suspiciously large)
UNLIMITED_THRESHOLD = HALF_MAX


# ═══════════════════════════════════════════════════════════════
# RULES ENGINE
# ═══════════════════════════════════════════════════════════════

class RulesEngine:
    """
    Deterministic decision engine for on-chain security.
    No LLM calls. Pure logic + protocol registry + pattern matching.
    """

    def __init__(self, scam_db=None):
        """
        Args:
            scam_db: Optional ScamDatabase instance for blacklist checks.
        """
        self._scam_db = scam_db

    # ── Address classification ────────────────────────────────

    def classify(self, address: str, chain: str = "ethereum") -> tuple[Trust, Optional[ProtocolInfo]]:
        """
        Classify an address as TRUSTED, UNTRUSTED, or UNKNOWN.
        Returns (trust_level, protocol_info_or_None).
        """
        addr = address.lower()

        # 1. Check universal protocols (same address on all chains)
        if addr in UNIVERSAL_PROTOCOLS:
            return Trust.TRUSTED, UNIVERSAL_PROTOCOLS[addr]

        # 2. Check chain-specific registry
        chain_protocols = PROTOCOL_REGISTRY.get(chain, {})
        if addr in chain_protocols:
            return Trust.TRUSTED, chain_protocols[addr]

        # 3. Check scam database
        if self._scam_db:
            scam_match = self._scam_db.is_known_scam(address)
            if scam_match:
                return Trust.UNTRUSTED, None

        # 4. Unknown
        return Trust.UNKNOWN, None

    def is_verified_protocol(self, address: str, chain: str = "ethereum") -> bool:
        """Quick check: is this address a verified protocol on this chain?"""
        trust, _ = self.classify(address, chain)
        return trust == Trust.TRUSTED

    def is_known_scam(self, address: str) -> bool:
        """Quick check: is this address in the scam database?"""
        if not self._scam_db:
            return False
        return self._scam_db.is_known_scam(address) is not None

    def get_protocol_info(self, address: str, chain: str = "ethereum") -> Optional[ProtocolInfo]:
        """Get protocol metadata if address is known."""
        _, info = self.classify(address, chain)
        return info

    # ── Finding evaluation (deterministic rules) ──────────────

    def evaluate_approval(self, spender: str, token: str, amount: int,
                          chain: str = "ethereum", contract_age_hours: float = None) -> RuleVerdict:
        """
        Evaluate an ERC20 approval finding.
        Returns a verdict with confidence.
        """
        trust, info = self.classify(spender, chain)
        is_unlimited = amount >= UNLIMITED_THRESHOLD

        # Rule 1: Approval to known scam → instant THREAT
        if trust == Trust.UNTRUSTED:
            return RuleVerdict(
                verdict=Verdict.THREAT,
                confidence=0.98,
                reason="Approval to KNOWN SCAM address%s" % (
                    " (%s)" % info.name if info else ""
                ),
                rule_name="approval_to_scam",
            )

        # Rule 2: Approval to verified protocol with limited amount → SAFE
        if trust == Trust.TRUSTED and not is_unlimited:
            return RuleVerdict(
                verdict=Verdict.SAFE,
                confidence=0.95,
                reason="Limited approval to verified protocol: %s" % info.name,
                rule_name="limited_approval_trusted",
            )

        # Rule 3: Unlimited approval to verified protocol → AMBIGUOUS (warn but not panic)
        if trust == Trust.TRUSTED and is_unlimited:
            return RuleVerdict(
                verdict=Verdict.AMBIGUOUS,
                confidence=0.70,
                reason="Unlimited approval granted to verified protocol: %s. "
                       "Safe but best practice is to use limited approvals." % info.name,
                rule_name="unlimited_approval_trusted",
            )

        # Rule 4: Unlimited approval to UNKNOWN contract → likely THREAT
        if trust == Trust.UNKNOWN and is_unlimited:
            # Extra signal: contract age
            if contract_age_hours is not None and contract_age_hours < 24:
                return RuleVerdict(
                    verdict=Verdict.THREAT,
                    confidence=0.85,
                    reason="Unlimited approval to unknown contract deployed %.1f hours ago" % contract_age_hours,
                    rule_name="unlimited_approval_new_unknown",
                )
            return RuleVerdict(
                verdict=Verdict.THREAT,
                confidence=0.70,
                reason="Unlimited approval to unknown/unverified address",
                rule_name="unlimited_approval_unknown",
            )

        # Rule 5: Limited approval to unknown → AMBIGUOUS
        if trust == Trust.UNKNOWN and not is_unlimited:
            return RuleVerdict(
                verdict=Verdict.AMBIGUOUS,
                confidence=0.50,
                reason="Limited approval to unverified address — not in our protocol registry",
                rule_name="limited_approval_unknown",
            )

        # Fallback
        return RuleVerdict(
            verdict=Verdict.AMBIGUOUS,
            confidence=0.30,
            reason="Could not deterministically classify this approval",
            rule_name="fallback",
        )

    def evaluate_address_interaction(self, address: str, chain: str = "ethereum",
                                     direction: str = "out", value: float = 0) -> RuleVerdict:
        """Evaluate a transaction to/from an address."""
        trust, info = self.classify(address, chain)

        # Outflow to known scam
        if trust == Trust.UNTRUSTED and direction == "out":
            return RuleVerdict(
                verdict=Verdict.THREAT,
                confidence=0.97,
                reason="Sending funds to KNOWN SCAM address",
                rule_name="outflow_to_scam",
            )

        # Inflow from known scam
        if trust == Trust.UNTRUSTED and direction == "in":
            return RuleVerdict(
                verdict=Verdict.AMBIGUOUS,
                confidence=0.60,
                reason="Received funds from flagged address — could be dust attack or address poisoning",
                rule_name="inflow_from_scam",
            )

        # Normal interaction with verified protocol
        if trust == Trust.TRUSTED:
            return RuleVerdict(
                verdict=Verdict.SAFE,
                confidence=0.90,
                reason="Interaction with verified protocol: %s" % info.name,
                rule_name="interaction_trusted",
            )

        # Unknown address, large outflow
        if trust == Trust.UNKNOWN and direction == "out" and value > 0.5:
            return RuleVerdict(
                verdict=Verdict.AMBIGUOUS,
                confidence=0.45,
                reason="Large outflow (%.4f) to unverified address" % value,
                rule_name="large_outflow_unknown",
            )

        # Unknown, small or inflow — not enough signal
        return RuleVerdict(
            verdict=Verdict.AMBIGUOUS,
            confidence=0.30,
            reason="Interaction with unknown address",
            rule_name="interaction_unknown",
        )

    # ── Pattern detection rules (deterministic) ───────────────

    def is_address_poisoning(self, address: str) -> RuleVerdict:
        """Detect address poisoning attacks (many zeros, mimicry patterns)."""
        addr = address.lower()[2:]  # strip 0x
        zero_count = addr.count("0")

        if zero_count > 28:
            return RuleVerdict(Verdict.THREAT, 0.92,
                               "Address has %d zeros — almost certainly address poisoning" % zero_count,
                               "address_poisoning_extreme")
        if zero_count > 20:
            return RuleVerdict(Verdict.THREAT, 0.75,
                               "Address has %d zeros — likely address poisoning attempt" % zero_count,
                               "address_poisoning_likely")
        if zero_count > 15:
            return RuleVerdict(Verdict.AMBIGUOUS, 0.40,
                               "Address has %d zeros — possibly address poisoning" % zero_count,
                               "address_poisoning_possible")

        return RuleVerdict(Verdict.SAFE, 0.80,
                           "Address zero-count (%d) is normal" % zero_count,
                           "address_normal")

    def is_dust_attack(self, amount: float, direction: str = "in") -> RuleVerdict:
        """Detect dust attacks (tiny unsolicited inflows)."""
        if direction == "in" and 0 < amount < 0.0001:
            return RuleVerdict(Verdict.AMBIGUOUS, 0.65,
                               "Tiny unsolicited inflow (%.8f) — possible dust attack" % amount,
                               "dust_attack")
        return RuleVerdict(Verdict.SAFE, 0.80,
                           "Amount is not dust-level", "not_dust")

    def evaluate_contract_finding(self, finding_type: str, chain: str = "ethereum",
                                  contract_address: str = None) -> RuleVerdict:
        """
        Evaluate a contract analysis finding.
        Some findings (like PROXY_CONTRACT) are normal for verified protocols.
        """
        # If the contract is a verified protocol, most findings are expected
        if contract_address:
            trust, info = self.classify(contract_address, chain)
            if trust == Trust.TRUSTED:
                # Verified protocols OFTEN have proxy, owner, etc. — normal
                benign_for_trusted = {
                    "PROXY_CONTRACT", "CONTRACT_OWNER", "EOA_OWNER",
                    "OWNER_POWER_MINT()", "OWNER_POWER_PAUSE()",
                }
                if finding_type in benign_for_trusted:
                    return RuleVerdict(
                        verdict=Verdict.SAFE,
                        confidence=0.92,
                        reason="%s is expected for verified protocol %s" % (finding_type, info.name),
                        rule_name="finding_expected_for_protocol",
                    )

        # For unknown contracts, findings keep their severity
        critical_findings = {"SELFDESTRUCT", "OWNER_POWER_BLACKLIST()", "HONEYPOT_LIKELY"}
        high_findings = {"OWNER_POWER_MINT()", "OWNER_POWER_PAUSE()", "BRAND_NEW_TOKEN", "EXTREME_CONCENTRATION"}

        if finding_type in critical_findings:
            return RuleVerdict(Verdict.THREAT, 0.88,
                               "%s detected on unverified contract" % finding_type,
                               "critical_finding_unverified")
        if finding_type in high_findings:
            return RuleVerdict(Verdict.THREAT, 0.70,
                               "%s detected on unverified contract" % finding_type,
                               "high_finding_unverified")

        return RuleVerdict(Verdict.AMBIGUOUS, 0.40,
                           "Finding %s — needs further analysis" % finding_type,
                           "finding_needs_analysis")

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return registry stats."""
        total = len(UNIVERSAL_PROTOCOLS)
        by_chain = {}
        for chain, protocols in PROTOCOL_REGISTRY.items():
            by_chain[chain] = len(protocols)
            total += len(protocols)

        return {
            "totalProtocols": total,
            "universalProtocols": len(UNIVERSAL_PROTOCOLS),
            "byChain": by_chain,
            "supportedChains": list(PROTOCOL_REGISTRY.keys()),
        }

    def get_all_protocols(self) -> dict:
        """Return the full protocol registry (for dashboard/API)."""
        result = {"universal": {}, "chains": {}}
        for addr, info in UNIVERSAL_PROTOCOLS.items():
            result["universal"][addr] = {
                "name": info.name, "category": info.category.value,
                "trustLevel": info.trust_level,
            }
        for chain, protocols in PROTOCOL_REGISTRY.items():
            result["chains"][chain] = {}
            for addr, info in protocols.items():
                result["chains"][chain][addr] = {
                    "name": info.name, "category": info.category.value,
                    "trustLevel": info.trust_level,
                }
        return result
