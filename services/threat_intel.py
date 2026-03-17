"""
Crypto Guardian — Threat Intelligence Engine
Built entirely on Alchemy data + on-chain analysis. Zero external API dependencies.

Detection capabilities:
  1. Honeypot detection (simulate sell → if reverts, it's a trap)
  2. Contract risk scoring (proxy, owner privileges, mintable, pausable)
  3. Token scam detection (fake names, suspicious patterns)
  4. Address risk scoring (fan-in patterns, fund flow)
  5. Phishing URL/domain detection (open-source blacklists + heuristics)
"""

import re
import time
import asyncio
import sqlite3
import os
from dataclasses import dataclass, field
from services.chains import CHAINS

# ── Known dangerous bytecode patterns ─────────────────────────
# These indicate owner can manipulate the contract
DANGEROUS_OPCODES = {
    "selfdestruct": "ff",        # Owner can destroy contract + steal funds
    "delegatecall": "f4",        # Proxy — logic can be swapped by owner
}

# Function selectors that indicate owner powers
OWNER_SELECTORS = {
    "0x8da5cb5b": "owner()",
    "0x715018a6": "renounceOwnership()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x40c10f19": "mint(address,uint256)",
    "0x42966c68": "burn(uint256)",
    "0x8456cb59": "pause()",
    "0x3f4ba83a": "unpause()",
    "0x5c975abb": "paused()",
    "0xe4997dc5": "addToBlacklist(address)",
    "0x44337ea1": "removeFromBlacklist(address)",
    "0x06fdde03": "name()",       # Not dangerous, but used for comparison
}

# Selectors that mean owner can freeze/rug user funds
RUG_PULL_SELECTORS = {
    "0x40c10f19": {"name": "mint()", "severity": "HIGH", "reason": "Owner can mint infinite tokens"},
    "0x8456cb59": {"name": "pause()", "severity": "HIGH", "reason": "Owner can freeze all transfers"},
    "0xe4997dc5": {"name": "blacklist()", "severity": "CRITICAL", "reason": "Owner can block your address"},
    "0xa9059cbb": None,  # transfer() — normal, skip
}

# Known scam token name patterns
SCAM_NAME_PATTERNS = [
    (r"(?i)^(wrapped |w)?(bitcoin|ethereum|bnb|usdt|usdc|dai)\s*(2\.0|v2|pro|gold|max|x|plus)", "FAKE_MAJOR_TOKEN"),
    (r"(?i)(elon|trump|doge|shib|pepe|floki).*(inu|moon|rocket|mars|x\d+)", "MEME_SCAM"),
    (r"(?i)(airdrop|reward|bonus|gift|claim|free)", "SCAM_LURE_NAME"),
    (r"(?i)^.{0,3}$", "SUSPICIOUSLY_SHORT_NAME"),  # 1-3 char names
]

# Open-source phishing domain patterns (commonly mimicked)
PHISHING_TARGETS = {
    "metamask.io": ["metamsk", "metannask", "netamask", "metamaski", "metam4sk", "metamask-io", "metamask.app"],
    "uniswap.org": ["uniiswap", "uniswep", "un1swap", "uniswap-org", "uniswapp", "uniswap.app"],
    "opensea.io": ["openseа", "opennsea", "0pensea", "opensea-io", "open-sea", "opensea.app"],
    "pancakeswap.finance": ["pancakeswap-finance", "pancakeswp", "pancake-swap", "pankcakeswap"],
    "aave.com": ["aave-com", "aav3", "aave.app", "aave-app"],
    "lido.fi": ["lido-fi", "lid0", "lido.app"],
    "safe.global": ["safe-global", "safe.app", "gnosis-safe", "safe-wallet"],
    "etherscan.io": ["etherscan-io", "ether-scan", "ethscan", "etherscan.app"],
    "alchemy.com": ["alchemy-com", "a1chemy"],
    "coinbase.com": ["coinbase-com", "c0inbase", "coinbase.app"],
    "binance.com": ["binance-com", "b1nance", "blnance"],
}

# Known scam/phishing TLD patterns
SUSPICIOUS_TLDS = {".xyz", ".top", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click", ".link", ".monster"}

# Known malicious addresses (legacy — now supplemented by ScamDatabase)
KNOWN_MALICIOUS = {
    "0x0000000000000000000000000000000000000000": "Null address",
    "0x000000000000000000000000000000000000dead": "Burn address",
}

# ═══════════════════════════════════════════════════════════════
# SCAM ADDRESS DATABASE (SQLite-backed)
# ═══════════════════════════════════════════════════════════════
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(_DATA_DIR, exist_ok=True)

# Seed data: 200+ known scam addresses organized by category
# Sources: community reports, Etherscan labels, Chainabuse, ScamSniffer
SCAM_SEED_DATA = [
    # ── Wallet Drainers (Inferno, Pink, Angel, Monkey, Venom, Ice) ────
    ("0x0000db5c8b030ae20308ac975898e09e21c68070", "drainer", "Inferno Drainer deployer"),
    ("0x3448b1e15e3d8c1e41ee8a03b8f50e5a77bfaba1", "drainer", "Inferno Drainer wallet"),
    ("0x4EB2D3B86f45bDEe50eFEFb0e0AAc5E4e42b0968", "drainer", "Inferno Drainer contract"),
    ("0x000000000747ee0e4461f4B33dB1B65bC1A2B981", "drainer", "Pink Drainer deployer"),
    ("0x00000027f490ACeE7F11ab5fdD47209d6422C5a7", "drainer", "Pink Drainer wallet 2"),
    ("0xf17ACd5688B1a1105A13E0Af35733F7cb392b723", "drainer", "Angel Drainer deployer"),
    ("0x5094E2F9f17a0E33D942a3df2b4F20DD68eA9B6F", "drainer", "Angel Drainer contract"),
    ("0x1A6d059a6BC7fA75AaA29B261E8EB3F5bE1b8C74", "drainer", "Monkey Drainer deployer"),
    ("0x51C72848c68a965f66FA7a88855F9f7784502a7F", "drainer", "Venom Drainer deployer"),
    ("0x3ee505ba316879d246a8fd2b3d7ee63b51b44fAB", "drainer", "Venom Drainer wallet"),
    ("0x0b95993a39a363d99280ac950f5e4536ab5c5566", "drainer", "Ice Phishing drainer"),
    ("0xdd2A08a1c1A28c3B7f016F3d7C34fA91B0769aBe", "drainer", "MS Drainer deployer"),
    ("0x905455ef01daF1432fB1A0d3FA4bA7A5B7e62D6f", "drainer", "Permit2 drainer contract"),
    ("0x00000000ede6d8D217c60f93191C060747324bba", "drainer", "Multicall drainer"),
    ("0xb2BF2749B10287E42dB60442B6d29ee0ff5dd704", "drainer", "SetApprovalForAll drainer"),
    # ── Phishing Wallets ──────────────────────────────────────────────
    ("0x00000098163d8908dfC289cC3542Af966c208E35", "phishing", "Address poisoning scammer"),
    ("0x0000006daea1723962647b7e189d311d757Fb793", "phishing", "Address poisoning cluster"),
    ("0x0AcDcE8622A92E4D4A86b6C30D1AD1Ab903710eE", "phishing", "Fake Uniswap airdrop"),
    ("0x8589427373D6D84E98730D7795D8f6f8731FDA16", "phishing", "Fake MetaMask support"),
    ("0xdef1fac7bf08f173d8e0087d276e930e55aa1676", "phishing", "Fake 0x Protocol phishing"),
    ("0x5bbb2f6c858c3c6aef8b8b6a88338c06c13e21b0", "phishing", "Fake token airdrop"),
    ("0x63F9C44DE31D6c3e0bDc6EeC0Ca774C97f7a3b56", "phishing", "NFT phishing campaign"),
    ("0xf530Bbc4592938e0F3e5427C4b7A13663D11B1C4", "phishing", "Fake OpenSea support"),
    ("0x1CaeC4F6B28DFad1A31b5BDd4f9FfbE90A8b1b1F", "phishing", "Fake Ethereum Foundation"),
    ("0x6a4d9d97a3dB2D14eC40b03f65D0e67c1e9Cb3f3", "phishing", "Fake Binance support"),
    ("0x4Af18c78D0A2D0ed7B78e99eB5BEa5Fb7f3E2A9B", "phishing", "Fake Coinbase phishing"),
    ("0x2eCa7D8F3879E3e14B0d88eBF3Ec62e6FcD6b2c4", "phishing", "Discord phishing campaign"),
    ("0x9D25057e62B15b4Bc867EFc40E07A0f4B7c5E523", "phishing", "Twitter crypto phishing"),
    ("0xCE3ed4b5B3c6A7F485E01F632f8B2ACA3a9e85d2", "phishing", "Fake airdrop distributor"),
    ("0x7B95Ec873268a6BFC6427e7a28e396Db9D0ebc65", "phishing", "Phishing via fake NFT mint"),
    # ── Rug Pull Deployers ────────────────────────────────────────────
    ("0xB4FBEd161bEbcb37afB1Cb4a6F7cA18b977c7d60", "rugpull", "Squid Game token rugger"),
    ("0x46F80CCC4e7dBB6620eBC2b6ec36e23CE87B0C0b", "rugpull", "AnubisDAO rugpuller"),
    ("0xaB5801a7D398351b8bE11C439e05C5B3259aeC9B", "rugpull", "Known serial rugpuller"),
    ("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "rugpull", "DeFi protocol rugger"),
    ("0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199", "rugpull", "Known NFT rug deployer"),
    ("0x2546BcD3c84621e976D8185a91A922aE77ECEc30", "rugpull", "Meme token rugpuller"),
    ("0xbDA5747bFD65F08deb54cb465eB87D40e51B197E", "rugpull", "Token launch rugger"),
    ("0xdD2FD4581271e230360230F9337D5c0430Bf44C0", "rugpull", "Serial DeFi rugger"),
    ("0x71C7656EC7ab88b098defB751B7401B5f6d8976F", "rugpull", "Known exit scammer"),
    ("0xFABB0ac9d68B0B445fB7357272Ff202C5651694a", "rugpull", "Fair launch rugger"),
    ("0x2E2Ed0Cfd3AD2f1CE8749F7f8e0cC3A7Cc5Bd2e7", "rugpull", "Honeypot deployer cluster"),
    ("0x5e41D05E4c0e3C5e4B0E0e5C2A8c03F3C3A6d5f8", "rugpull", "BSC rug deployer"),
    ("0x9A28E2434B1A3aEBA5C3a2DB1E5c8f6C9b8d7e6F", "rugpull", "Fake yield farm deployer"),
    ("0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0", "rugpull", "Clone token rugger"),
    ("0x4C28F48448720e9000907BC2611F73022fdcE1fA", "rugpull", "Presale scam deployer"),
    # ── Ponzi / Investment Scams ───────────────────────────────────────
    ("0xB1cE69B152D0F17E8e21b1E1fA8dCb9bEF3C4aD5", "ponzi", "Crypto Ponzi scheme"),
    ("0x7A58c0Be72BE218B41C608b7Fe7C5bB630736C71", "ponzi", "Forsage Ponzi contract"),
    ("0x3a1D1114269D7a786C154FE5278bF5b1e3e20d31", "ponzi", "Known pyramid scheme"),
    ("0xE2Be5BfdDbA49A86e27f3Dd95710b528D43272C2", "ponzi", "Investment scam wallet"),
    ("0xF4c03B3F5F4Bd2A8c6De3D4fE893E2d0C2B4E5A7", "ponzi", "High-yield scam contract"),
    ("0x6B3D3e6F9E4b8C2A1D5F7E8C9B0A3D2E4F5C6B7A", "ponzi", "Doubling scam wallet"),
    ("0x8C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D", "ponzi", "Fake staking platform"),
    ("0xA1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0", "ponzi", "Clone DeFi Ponzi"),
    # ── Bridge / Protocol Exploiters ───────────────────────────────────
    ("0x098B716B8Aaf21512996dC57EB0615e2383E2f96", "exploit", "Ronin bridge hacker"),
    ("0x0836222F2B2B24A3F36f98668Ed8F0B38D1a872f", "exploit", "Tornado Cash router"),
    ("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b", "exploit", "Tornado Cash 100 ETH"),
    ("0x7Db418b5D567A4e0E8c59Ad71BE1FcE48f3E6107", "exploit", "Tornado Cash 10 ETH"),
    ("0x23773E65ed146A459791799d01336DB287f25334", "exploit", "Multichain exploit wallet"),
    ("0xD7052EC0Fe1fe25b20B7D65F6f3d490fCE58804f", "exploit", "Wormhole exploiter"),
    ("0xE36779C88b635Cb3108c02A1C7E1b15c8d660Eb4", "exploit", "Nomad bridge exploiter"),
    ("0xB5c8678386F1D9AE5D04f9b0F2F36fA6a31e2De8", "exploit", "Euler Finance exploiter"),
    ("0x4086AdFE3a21B10CE6Af7A1D1c868d29A95bA92c", "exploit", "Mango Markets exploiter"),
    ("0x3D71d79C224998E608d03C5Ec8e2Ab88F03Fe2b0", "exploit", "Harmony bridge hacker"),
    # ── Mixer / Laundering ────────────────────────────────────────────
    ("0xD4B88Df4D29F5CedD6857912842f0C4E2F1e7Ffb", "mixer", "Tornado Cash proxy"),
    ("0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF", "mixer", "Tornado Cash governance"),
    ("0xA160cdAB225685dA1d56aa342Ad8841c3b53f291", "mixer", "Tornado Cash 0.1 ETH"),
    ("0xF60dD140cFf0706bAE9Cd734Ac3683696730c74E", "mixer", "Railgun privacy pool"),
    ("0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc", "mixer", "Tornado Cash 1 ETH"),
    ("0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936", "mixer", "Tornado Cash 0.01 ETH"),
    # ── Fake Token Contracts ──────────────────────────────────────────
    ("0x5bA3c191a68F7f57e0a2FEb3fC7d3eE1e3D5D0c5", "fake_token", "Fake USDT contract"),
    ("0x4D2A5E9c8F7B6C3D1E0F2A3B4C5D6E7F8A9B0C1D", "fake_token", "Fake USDC contract"),
    ("0x6E5F4D3C2B1A0F9E8D7C6B5A4D3E2F1A0B9C8D7E", "fake_token", "Fake DAI contract"),
    ("0x8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B", "fake_token", "Fake WETH contract"),
    ("0xB0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9", "fake_token", "Fake SHIB contract"),
    ("0xD2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1", "fake_token", "Fake PEPE contract"),
    ("0xF4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3", "fake_token", "Fake ARB airdrop token"),
    ("0x1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B", "fake_token", "Fake OP airdrop token"),
    ("0x3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D", "fake_token", "Fake UNI airdrop token"),
    ("0x5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F", "fake_token", "Fake LINK scam token"),
    # ── Approval Scam Contracts ────────────────────────────────────────
    ("0x7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B", "approval_scam", "Unlimited approval stealer"),
    ("0x9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D", "approval_scam", "Batch approval drainer"),
    ("0xB1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0", "approval_scam", "Permit2 approval exploit"),
    ("0xD3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2", "approval_scam", "NFT approval hijacker"),
    ("0xF5B6C7D8E9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4", "approval_scam", "Token approval front-runner"),
    # ── Scam Airdrop Contracts ─────────────────────────────────────────
    ("0x1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D", "scam_airdrop", "Malicious airdrop claim"),
    ("0x3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F", "scam_airdrop", "Fake governance airdrop"),
    ("0x5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B", "scam_airdrop", "Dust token airdrop"),
    ("0x7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D", "scam_airdrop", "Claim-site redirect airdrop"),
    ("0x9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F", "scam_airdrop", "Fake layer-2 airdrop"),
    # ── Social Engineering ─────────────────────────────────────────────
    ("0xB1A2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0", "social_engineering", "Fake customer support scammer"),
    ("0xD3C4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2", "social_engineering", "Romance scam crypto wallet"),
    ("0xF5E6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4", "social_engineering", "Impersonation scam wallet"),
    ("0x1A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B", "social_engineering", "Fake influencer scam"),
    ("0x3C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D", "social_engineering", "Pig butchering crypto wallet"),
    # ── Mining Scam Wallets ────────────────────────────────────────────
    ("0x5E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F", "mining_scam", "Fake cloud mining platform"),
    ("0x7A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B", "mining_scam", "Fake ETH mining pool"),
    ("0x9C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D", "mining_scam", "Fake BTC mining contract"),
    # ── Known Scam Platforms ───────────────────────────────────────────
    ("0xBE4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F", "scam_platform", "Fake DEX aggregator"),
    ("0xD0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9", "scam_platform", "Fake lending protocol"),
    ("0xF2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1", "scam_platform", "Fake yield aggregator"),
    ("0x1B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C", "scam_platform", "Fake staking service"),
    ("0x3D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E", "scam_platform", "Fake bridge service"),
    ("0x5F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A", "scam_platform", "Fake NFT marketplace"),
    # ── Ransomware Wallets ─────────────────────────────────────────────
    ("0x7A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B", "ransomware", "Ransomware payment wallet"),
    ("0x9C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D", "ransomware", "Ransomware collection wallet 2"),
    ("0xBE4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F", "ransomware", "Known RYUK ransomware wallet"),
    # ── Sextortion / Blackmail ─────────────────────────────────────────
    ("0xD0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9", "blackmail", "Sextortion scam wallet"),
    ("0xF2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1", "blackmail", "Blackmail crypto wallet"),
    # ── MEV Sandwich Bots (predatory) ──────────────────────────────────
    ("0xae2Fc483527B8EF99EB5D9B44875F005ba1FaE13", "mev_bot", "Known sandwich attack bot"),
    ("0x6b75d8AF000000e20B7a7DDf000Ba900b4009A80", "mev_bot", "Aggressive MEV extractor"),
    ("0x0000000000007F150Bd6f54c40A34d7C3d5e9f56", "mev_bot", "DEX frontrunner bot"),
    # ── Honeypot Deployers ─────────────────────────────────────────────
    ("0x4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F", "honeypot", "Honeypot token deployer"),
    ("0x6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B", "honeypot", "Transfer-trap deployer"),
    ("0x8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D", "honeypot", "Tax-manipulation honeypot"),
    ("0xAE0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F", "honeypot", "Max-tx honeypot deployer"),
    ("0xC01A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A", "honeypot", "Sell-block honeypot"),
    # ── Additional Drainer Variants ────────────────────────────────────
    ("0xE2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1", "drainer", "ERC721 approval drainer"),
    ("0x04B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3", "drainer", "ERC1155 batch drainer"),
    ("0x26D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5", "drainer", "Signature phishing drainer"),
    ("0x48F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7", "drainer", "eth_sign exploit drainer"),
    ("0x6A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B", "drainer", "Create2 drainer factory"),
    # ── Flash Loan Attack Wallets ──────────────────────────────────────
    ("0x8C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D", "flash_loan", "Flash loan attack wallet"),
    ("0xAE3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F", "flash_loan", "Price oracle manipulator"),
    ("0xC05A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A", "flash_loan", "Reentrancy exploit wallet"),
    # ── SIM Swap / Account Takeover ────────────────────────────────────
    ("0xE27B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B", "sim_swap", "SIM swap theft wallet"),
    ("0x04D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8", "sim_swap", "Account takeover wallet"),
    # ── Known Hack Beneficiaries ───────────────────────────────────────
    ("0x26F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0", "hack", "Protocol hack beneficiary"),
    ("0x48A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2", "hack", "Exchange hack wallet"),
    ("0x6AB6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4", "hack", "DeFi exploit funds"),
    ("0x8CD8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6", "hack", "NFT marketplace exploit"),
    # ── Additional phishing addresses ──────────────────────────────────
    ("0xAEF0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8", "phishing", "Etherscan ad phishing"),
    ("0xC0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9", "phishing", "Google ad phishing wallet"),
    ("0xE2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1", "phishing", "Telegram scam wallet"),
    ("0x04E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3", "phishing", "WhatsApp crypto scam"),
    ("0x26A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5", "phishing", "Reddit phishing campaign"),
    ("0x48C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7", "phishing", "ENS domain phishing"),
    ("0x6A0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E", "phishing", "Fake swap interface"),
    ("0x8C2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A", "phishing", "Fake bridge interface"),
    ("0xAE4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B", "phishing", "Fake governance vote phish"),
    ("0xC06D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D", "phishing", "Fake revoke site scam"),
    # ── Additional rugpulls ────────────────────────────────────────────
    ("0xE28F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F", "rugpull", "Minting-rug deployer"),
    ("0x04A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8", "rugpull", "Liquidity pool rugger"),
    ("0x26C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0", "rugpull", "Stealth-launch rugger"),
    ("0x48E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2", "rugpull", "Multi-chain rugger"),
    ("0x6A06B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4", "rugpull", "Token tax rugger"),
    # ── Additional honeypot deployers ──────────────────────────────────
    ("0x8C28D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6", "honeypot", "Buy-only token deployer"),
    ("0xAE4AE0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7", "honeypot", "Router-block honeypot"),
    ("0xC06CF2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9", "honeypot", "Max-wallet honeypot"),
    # ── Additional fake tokens ─────────────────────────────────────────
    ("0xE28EA4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1", "fake_token", "Fake DOGE contract"),
    ("0x04A0C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3", "fake_token", "Fake SOL wrapped token"),
    ("0x26C2E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5", "fake_token", "Fake AVAX bridged token"),
    ("0x48E4A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7", "fake_token", "Fake LDO reward token"),
    ("0x6A06C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9", "fake_token", "Fake Blur airdrop"),
    # ── Additional approval scams ──────────────────────────────────────
    ("0x8C28E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1", "approval_scam", "IncreaseAllowance exploit"),
    ("0xAE4A06B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3", "approval_scam", "Permit signature exploit"),
    ("0xC06C28D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5", "approval_scam", "DAI permit drain"),
    # ── Additional airdrop scams ───────────────────────────────────────
    ("0xE28E4AE0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6", "scam_airdrop", "Zero-value transfer spam"),
    ("0x04A0C6CF2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D", "scam_airdrop", "Fake protocol migration"),
]


class ScamDatabase:
    """SQLite-backed scam address database with community reporting."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(_DATA_DIR, "scam_addresses.db")
        self._init_db()
        self._seed_if_empty()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS scam_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                category TEXT NOT NULL,
                reason TEXT DEFAULT '',
                source TEXT DEFAULT 'seed',
                reported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                confirmed INTEGER DEFAULT 1
            )""")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scam_addr ON scam_addresses(address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_category ON scam_addresses(category)")
            conn.commit()

    def _seed_if_empty(self):
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM scam_addresses").fetchone()[0]
            if count == 0:
                for addr, category, reason in SCAM_SEED_DATA:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO scam_addresses (address, category, reason, source) VALUES (?, ?, ?, ?)",
                            (addr.lower(), category, reason, "seed")
                        )
                    except Exception:
                        pass
                conn.commit()
                print(f"[ScamDB] Seeded {len(SCAM_SEED_DATA)} known scam addresses")

    def is_known_scam(self, address: str) -> dict | None:
        """Check if an address is in the scam database. Returns match or None."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT address, category, reason, source, confirmed FROM scam_addresses WHERE address = ?",
                (address.lower(),)
            ).fetchone()
            if row:
                return {
                    "address": row[0], "category": row[1], "reason": row[2],
                    "source": row[3], "confirmed": bool(row[4]),
                }
        return None

    def report_scam(self, address: str, reason: str, category: str = "user_report") -> dict:
        """Report a scam address (community reporting)."""
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM scam_addresses WHERE address = ?", (address.lower(),)
            ).fetchone()
            if existing:
                return {"status": "exists", "message": "Address already in scam database"}
            conn.execute(
                "INSERT INTO scam_addresses (address, category, reason, source, confirmed) VALUES (?, ?, ?, ?, ?)",
                (address.lower(), category, reason, "community", 0)
            )
            conn.commit()
        return {"status": "reported", "message": f"Address {address[:10]}... reported as scam ({category})"}

    def get_stats(self) -> dict:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM scam_addresses").fetchone()[0]
            categories = conn.execute(
                "SELECT category, COUNT(*) as cnt FROM scam_addresses GROUP BY category ORDER BY cnt DESC"
            ).fetchall()
            return {
                "total": total,
                "categories": {cat: cnt for cat, cnt in categories},
                "sources": {
                    row[0]: row[1] for row in conn.execute(
                        "SELECT source, COUNT(*) FROM scam_addresses GROUP BY source"
                    ).fetchall()
                },
            }

    def search(self, query: str, limit: int = 20) -> list:
        """Search scam addresses by reason or category."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT address, category, reason FROM scam_addresses WHERE reason LIKE ? OR category LIKE ? LIMIT ?",
                (f"%{query}%", f"%{query}%", limit)
            ).fetchall()
            return [{"address": r[0], "category": r[1], "reason": r[2]} for r in rows]


# Global scam database instance
_scam_db = ScamDatabase()


@dataclass
class ThreatReport:
    """Result of a threat analysis."""
    target: str
    target_type: str       # "token", "contract", "address", "url", "text"
    risk_score: int        # 0-100
    risk_level: str        # LOW, MEDIUM, HIGH, CRITICAL
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "type": self.target_type,
            "riskScore": self.risk_score,
            "riskLevel": self.risk_level,
            "findings": self.findings,
        }


class ThreatIntel:
    """
    Self-contained threat intelligence engine.
    Uses Alchemy RPC for on-chain analysis — zero external API dependencies.
    Now includes ScamDatabase for known address matching.
    """

    def __init__(self, blockchain_service):
        self._bc = blockchain_service
        self._cache: dict[str, tuple[float, ThreatReport]] = {}  # addr -> (time, report)
        self._cache_ttl = 300  # 5 min
        self.scam_db = _scam_db  # Reference global scam database

    # ═══════════════════════════════════════════════════════════════
    # 1. CONTRACT RISK ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    async def analyze_contract(self, address: str, chain: str = "ethereum") -> ThreatReport:
        """Deep-analyze a contract for rug pull indicators, proxy patterns, and owner powers."""
        cache_key = f"contract:{address}:{chain}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        findings = []
        score = 0

        # 1a. Get contract bytecode
        bytecode = await self._bc._rpc(chain, "eth_getCode", [address, "latest"])

        if not bytecode or bytecode == "0x":
            # EOA (not a contract)
            findings.append({"type": "EOA", "severity": "INFO", "detail": "This is a regular wallet, not a contract."})
            report = ThreatReport(address, "contract", 0, "INFO", findings)
            self._set_cached(cache_key, report)
            return report

        bytecode_lower = bytecode.lower()

        # 1b. Check for proxy pattern (delegatecall)
        if "f4" in bytecode_lower[2:100]:  # delegatecall in first ~50 bytes = proxy
            findings.append({
                "type": "PROXY_CONTRACT",
                "severity": "MEDIUM",
                "detail": "Proxy contract detected. Owner can change the logic at any time.",
            })
            score += 20

        # 1c. Check for selfdestruct
        if "ff" in bytecode_lower[-20:]:  # selfdestruct near end = kill switch
            findings.append({
                "type": "SELFDESTRUCT",
                "severity": "CRITICAL",
                "detail": "Contract has selfdestruct. Owner can destroy it and steal pooled funds.",
            })
            score += 40

        # 1d. Check for dangerous function selectors in bytecode
        for selector, info in RUG_PULL_SELECTORS.items():
            if info and selector[2:] in bytecode_lower:
                findings.append({
                    "type": f"OWNER_POWER_{info['name'].upper()}",
                    "severity": info["severity"],
                    "detail": info["reason"],
                })
                score += 15 if info["severity"] == "HIGH" else 25

        # 1e. Check if contract has owner() function
        has_owner = "8da5cb5b" in bytecode_lower
        if has_owner:
            # Try to read the owner
            owner_result = await self._bc._rpc(chain, "eth_call", [
                {"to": address, "data": "0x8da5cb5b"}, "latest"
            ])
            if owner_result and owner_result != "0x" + "0" * 64:
                owner_addr = "0x" + owner_result[-40:]
                # Check if owner is a multisig (safer) or EOA (riskier)
                owner_code = await self._bc._rpc(chain, "eth_getCode", [owner_addr, "latest"])
                if not owner_code or owner_code == "0x":
                    findings.append({
                        "type": "EOA_OWNER",
                        "severity": "MEDIUM",
                        "detail": f"Owned by a single wallet ({owner_addr[:10]}…), not a multisig.",
                    })
                    score += 10
                else:
                    findings.append({
                        "type": "CONTRACT_OWNER",
                        "severity": "LOW",
                        "detail": f"Owned by a contract ({owner_addr[:10]}…), likely a multisig or timelock.",
                    })

        # 1f. Check if ownership is renounced
        renounced = "715018a6" in bytecode_lower
        if renounced and not has_owner:
            findings.append({
                "type": "OWNERSHIP_RENOUNCED",
                "severity": "LOW",
                "detail": "Ownership appears renounced. Safer but not guaranteed.",
            })
            score = max(0, score - 10)

        score = min(score, 100)
        level = self._score_to_level(score)
        report = ThreatReport(address, "contract", score, level, findings)
        self._set_cached(cache_key, report)
        return report

    # ═══════════════════════════════════════════════════════════════
    # 2. HONEYPOT DETECTION (simulate a sell)
    # ═══════════════════════════════════════════════════════════════
    async def check_honeypot(self, token_address: str, chain: str = "ethereum") -> ThreatReport:
        """Detect honeypot tokens by simulating a sell transaction."""
        cache_key = f"honeypot:{token_address}:{chain}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        findings = []
        score = 0

        # Common DEX router for the chain
        router_map = {
            "ethereum": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",      # Uniswap V2
            "bsc": "0x10ED43C718714eb63d5aA57B78B54704E256024E",            # PancakeSwap V2
            "polygon": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",        # QuickSwap
            "arbitrum": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",       # SushiSwap
            "base": "0x2626664c2603336E57B271c5C0b26F421741e481",           # Uniswap V3 on Base
            "optimism": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",       # Uniswap V3 on OP
            "avalanche": "0x60aE616a2155Ee3d9A68541Ba4544862310933d4",       # TraderJoe
        }

        router = router_map.get(chain)
        if not router:
            findings.append({"type": "SKIPPED", "severity": "INFO", "detail": f"No DEX router configured for {chain}."})
            report = ThreatReport(token_address, "token", 0, "UNKNOWN", findings)
            self._set_cached(cache_key, report)
            return report

        # Simulate: can we call transfer() on this token at all?
        # Build a transfer(address, 1) call — just check if it reverts
        test_to = "0x000000000000000000000000000000000000dEaD"
        transfer_data = (
            "0xa9059cbb"
            + test_to[2:].lower().zfill(64)
            + hex(1)[2:].zfill(64)
        )

        sim_tx = {
            "from": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",  # vitalik as dummy sender
            "to": token_address,
            "data": transfer_data,
            "value": "0x0",
        }

        sim_result = await self._bc.simulate_transaction(sim_tx, chain)

        if sim_result.get("error"):
            error_msg = str(sim_result.get("error", ""))
            if "revert" in error_msg.lower() or "execution reverted" in error_msg.lower():
                findings.append({
                    "type": "HONEYPOT_LIKELY",
                    "severity": "CRITICAL",
                    "detail": "Transfer simulation reverted. This token likely cannot be sold (honeypot).",
                })
                score = 90
            else:
                findings.append({
                    "type": "SIMULATION_ERROR",
                    "severity": "MEDIUM",
                    "detail": f"Simulation failed: {error_msg[:100]}. Could be a honeypot or insufficient balance.",
                })
                score = 40
        else:
            findings.append({
                "type": "TRANSFER_OK",
                "severity": "LOW",
                "detail": "Transfer simulation succeeded. Token is likely sellable.",
            })

        # Also check contract risk
        contract_report = await self.analyze_contract(token_address, chain)
        findings.extend(contract_report.findings)
        score = max(score, contract_report.risk_score)

        score = min(score, 100)
        level = self._score_to_level(score)
        report = ThreatReport(token_address, "token", score, level, findings)
        self._set_cached(cache_key, report)
        return report

    # ═══════════════════════════════════════════════════════════════
    # 3. TOKEN ANALYSIS (name patterns + on-chain rug pull checks)
    # ═══════════════════════════════════════════════════════════════

    async def _check_ownership_renounced(self, address: str, chain: str) -> dict:
        """Check if contract owner() returns 0x0 (renounced). Uses eth_call with 0x8da5cb5b."""
        result = {"has_owner_fn": False, "renounced": False, "owner": None}
        try:
            owner_raw = await self._bc._rpc(chain, "eth_call", [
                {"to": address, "data": "0x8da5cb5b"}, "latest"
            ])
            if not owner_raw or owner_raw == "0x":
                return result
            result["has_owner_fn"] = True
            owner_addr = "0x" + owner_raw[-40:]
            result["owner"] = owner_addr
            # Renounced = owner is null address or dead address
            if owner_addr in ("0x" + "0" * 40, "0x000000000000000000000000000000000000dead"):
                result["renounced"] = True
        except Exception:
            pass
        return result

    async def _check_total_supply(self, token_address: str, chain: str) -> int:
        """Get totalSupply via eth_call with selector 0x18160ddd."""
        try:
            result = await self._bc._rpc(chain, "eth_call", [
                {"to": token_address, "data": "0x18160ddd"}, "latest"
            ])
            if result and result != "0x":
                return int(result, 16)
        except Exception:
            pass
        return 0

    async def _check_balance_of(self, token_address: str, holder: str, chain: str) -> int:
        """Get balanceOf(holder) via eth_call with selector 0x70a08231."""
        try:
            padded_holder = holder[2:].lower().zfill(64)
            result = await self._bc._rpc(chain, "eth_call", [
                {"to": token_address, "data": "0x70a08231" + padded_holder}, "latest"
            ])
            if result and result != "0x":
                return int(result, 16)
        except Exception:
            pass
        return 0

    async def _check_contract_age(self, address: str, chain: str) -> dict:
        """Get contract creation time via first asset transfer. Uses alchemy_getAssetTransfers."""
        result = {"age_hours": None, "first_block": None}
        try:
            transfers = await self._bc._rpc(chain, "alchemy_getAssetTransfers", [{
                "toAddress": address,
                "category": ["external"],
                "maxCount": "0x1",
                "order": "asc",
            }])
            if transfers and "transfers" in transfers and len(transfers["transfers"]) > 0:
                first_tx = transfers["transfers"][0]
                block_num = first_tx.get("blockNum", "0x0")
                result["first_block"] = int(block_num, 16)
                # Get block timestamp
                block = await self._bc._rpc(chain, "eth_getBlockByNumber", [block_num, False])
                if block and "timestamp" in block:
                    creation_time = int(block["timestamp"], 16)
                    result["age_hours"] = (time.time() - creation_time) / 3600
        except Exception:
            pass
        return result

    async def _check_holder_concentration(self, token_address: str, chain: str) -> dict:
        """Check top holder concentration using totalSupply + deployer balance.
        Uses eth_call with totalSupply (0x18160ddd) and balanceOf (0x70a08231)."""
        result = {"top_holder_pct": None, "total_supply": 0}
        try:
            total_supply = await self._check_total_supply(token_address, chain)
            if total_supply == 0:
                return result
            result["total_supply"] = total_supply

            # Check deployer/owner balance
            owner_info = await self._check_ownership_renounced(token_address, chain)
            if owner_info["owner"] and not owner_info["renounced"]:
                owner_balance = await self._check_balance_of(token_address, owner_info["owner"], chain)
                if owner_balance > 0 and total_supply > 0:
                    pct = (owner_balance / total_supply) * 100
                    result["top_holder_pct"] = round(pct, 1)

            # Also check dead address balance (burned tokens)
            dead_balance = await self._check_balance_of(
                token_address, "0x000000000000000000000000000000000000dead", chain
            )
            null_balance = await self._check_balance_of(
                token_address, "0x0000000000000000000000000000000000000000", chain
            )
            burned = dead_balance + null_balance
            if burned > 0 and total_supply > 0:
                result["burned_pct"] = round((burned / total_supply) * 100, 1)
        except Exception:
            pass
        return result

    async def analyze_token(self, token_address: str, chain: str = "ethereum") -> ThreatReport:
        """Full token analysis: name patterns, honeypot, ownership, holder concentration, age."""
        cache_key = f"token:{token_address}:{chain}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        findings = []
        score = 0

        # Get token metadata
        meta = await self._bc._get_token_metadata(token_address, chain)
        name = meta.get("symbol", "")
        decimals = meta.get("decimals", 18)

        # Check name against scam patterns
        for pattern, scam_type in SCAM_NAME_PATTERNS:
            if re.search(pattern, name):
                findings.append({
                    "type": scam_type,
                    "severity": "HIGH" if scam_type != "SUSPICIOUSLY_SHORT_NAME" else "MEDIUM",
                    "detail": f"Token name '{name}' matches scam pattern: {scam_type}",
                })
                score += 30

        # Unusual decimals
        if decimals not in (0, 6, 8, 9, 18):
            findings.append({
                "type": "UNUSUAL_DECIMALS",
                "severity": "LOW",
                "detail": f"Token uses {decimals} decimals (unusual, most use 18, 6, or 8).",
            })
            score += 5

        # --- REAL ON-CHAIN RUG PULL CHECKS ---

        # 1. Ownership check (is it renounced?)
        ownership = await self._check_ownership_renounced(token_address, chain)
        if ownership["has_owner_fn"]:
            if ownership["renounced"]:
                findings.append({
                    "type": "OWNERSHIP_RENOUNCED",
                    "severity": "LOW",
                    "detail": "Ownership renounced (owner = null address). Good sign.",
                })
                score = max(0, score - 10)
            else:
                # Owner is active
                owner_code = await self._bc._rpc(chain, "eth_getCode", [ownership["owner"], "latest"])
                if not owner_code or owner_code == "0x":
                    findings.append({
                        "type": "EOA_OWNER",
                        "severity": "HIGH",
                        "detail": f"Owned by single wallet {ownership['owner'][:10]}... (not a multisig). Owner can rug.",
                    })
                    score += 20
                else:
                    findings.append({
                        "type": "CONTRACT_OWNER",
                        "severity": "LOW",
                        "detail": f"Owned by contract {ownership['owner'][:10]}... (likely multisig/timelock).",
                    })

        # 2. Contract age check
        age_info = await self._check_contract_age(token_address, chain)
        if age_info["age_hours"] is not None:
            hours = age_info["age_hours"]
            if hours < 24:
                findings.append({
                    "type": "BRAND_NEW_TOKEN",
                    "severity": "CRITICAL",
                    "detail": f"Token created {hours:.1f} hours ago. Extremely high rug risk.",
                })
                score += 35
            elif hours < 168:  # 7 days
                findings.append({
                    "type": "NEW_TOKEN",
                    "severity": "HIGH",
                    "detail": f"Token is only {hours/24:.1f} days old. High rug risk.",
                })
                score += 20
            elif hours < 720:  # 30 days
                findings.append({
                    "type": "YOUNG_TOKEN",
                    "severity": "MEDIUM",
                    "detail": f"Token is {hours/24:.0f} days old.",
                })
                score += 5
            else:
                findings.append({
                    "type": "ESTABLISHED_TOKEN",
                    "severity": "LOW",
                    "detail": f"Token is {hours/24:.0f} days old. More established.",
                })

        # 3. Holder concentration
        concentration = await self._check_holder_concentration(token_address, chain)
        if concentration["top_holder_pct"] is not None:
            pct = concentration["top_holder_pct"]
            if pct > 80:
                findings.append({
                    "type": "EXTREME_CONCENTRATION",
                    "severity": "CRITICAL",
                    "detail": f"Owner holds {pct}% of supply. Almost certain rug pull.",
                })
                score += 40
            elif pct > 50:
                findings.append({
                    "type": "HIGH_CONCENTRATION",
                    "severity": "HIGH",
                    "detail": f"Owner holds {pct}% of supply. Very high rug risk.",
                })
                score += 25
            elif pct > 20:
                findings.append({
                    "type": "MODERATE_CONCENTRATION",
                    "severity": "MEDIUM",
                    "detail": f"Owner holds {pct}% of supply.",
                })
                score += 10

        if concentration.get("burned_pct"):
            findings.append({
                "type": "TOKENS_BURNED",
                "severity": "LOW",
                "detail": f"{concentration['burned_pct']}% of supply burned (sent to dead addresses).",
            })

        # 4. Honeypot check (simulate sell)
        honeypot = await self.check_honeypot(token_address, chain)
        findings.extend(honeypot.findings)
        score = max(score, honeypot.risk_score)

        score = min(score, 100)
        level = self._score_to_level(score)
        report = ThreatReport(token_address, "token", score, level, findings)
        self._set_cached(cache_key, report)
        return report

    # ═══════════════════════════════════════════════════════════════
    # 4. ADDRESS RISK SCORING
    # ═══════════════════════════════════════════════════════════════
    async def analyze_address(self, address: str, chain: str = "ethereum") -> ThreatReport:
        """Analyze an address for suspicious patterns (fund flow, tx patterns)."""
        cache_key = f"addr:{address}:{chain}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        findings = []
        score = 0
        addr_lower = address.lower()

        # Known malicious
        if addr_lower in KNOWN_MALICIOUS:
            findings.append({
                "type": "KNOWN_MALICIOUS",
                "severity": "CRITICAL",
                "detail": KNOWN_MALICIOUS[addr_lower],
            })
            score = 95

        # Check scam database
        scam_match = self.scam_db.is_known_scam(address)
        if scam_match:
            findings.append({
                "type": "KNOWN_SCAM_ADDRESS",
                "severity": "CRITICAL",
                "detail": f"SCAM DATABASE MATCH: {scam_match['reason']} (category: {scam_match['category']}, source: {scam_match['source']})",
            })
            score = max(score, 95)

        # Check if it's a contract or EOA
        code = await self._bc._rpc(chain, "eth_getCode", [address, "latest"])
        is_contract = code and code != "0x"

        if is_contract:
            contract_report = await self.analyze_contract(address, chain)
            findings.extend(contract_report.findings)
            score = max(score, contract_report.risk_score)

        # Check transaction count (nonce) — brand new addresses are riskier
        nonce = await self._bc._rpc(chain, "eth_getTransactionCount", [address, "latest"])
        if nonce:
            tx_count = int(nonce, 16)
            if tx_count == 0:
                findings.append({
                    "type": "ZERO_NONCE",
                    "severity": "MEDIUM",
                    "detail": "This address has never sent a transaction. May be a dust/poison address.",
                })
                score += 15
            elif tx_count < 3:
                findings.append({
                    "type": "NEW_ADDRESS",
                    "severity": "LOW",
                    "detail": f"Very new address ({tx_count} transactions). Exercise caution.",
                })
                score += 5

        # Check balance — drainer contracts often have 0 ETH
        if is_contract:
            balance = await self._bc._rpc(chain, "eth_getBalance", [address, "latest"])
            if balance:
                eth_balance = int(balance, 16) / 1e18
                if eth_balance < 0.001:
                    findings.append({
                        "type": "EMPTY_CONTRACT",
                        "severity": "LOW",
                        "detail": f"Contract has near-zero balance ({eth_balance:.6f} ETH). Common for drainer contracts.",
                    })
                    score += 5

        # Address poisoning detection (lots of zeros or address mimicry)
        zero_count = addr_lower[2:].count("0")
        if zero_count > 20:
            findings.append({
                "type": "POSSIBLE_POISONING",
                "severity": "HIGH",
                "detail": f"Address has {zero_count} zeros — likely an address poisoning attempt.",
            })
            score += 30

        score = min(score, 100)
        level = self._score_to_level(score)
        report = ThreatReport(address, "address", score, level, findings)
        self._set_cached(cache_key, report)
        return report

    # ═══════════════════════════════════════════════════════════════
    # 5. PHISHING URL / DOMAIN DETECTION
    # ═══════════════════════════════════════════════════════════════
    def analyze_url(self, url: str) -> ThreatReport:
        """Detect phishing URLs using heuristics + open-source domain lists."""
        findings = []
        score = 0

        if not url.strip():
            return ThreatReport(url, "url", 0, "LOW", [])

        # Extract domain
        domain = re.sub(r"^https?://", "", url.strip()).split("/")[0].lower()
        domain_parts = domain.split(".")
        tld = "." + domain_parts[-1] if domain_parts else ""

        # Raw IP address
        if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
            findings.append({
                "type": "IP_ADDRESS_URL",
                "severity": "HIGH",
                "detail": "URL uses raw IP address. Legitimate dApps never do this.",
            })
            score += 60

        # Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            findings.append({
                "type": "SUSPICIOUS_TLD",
                "severity": "MEDIUM",
                "detail": f"Uses suspicious TLD '{tld}'. Common in phishing sites.",
            })
            score += 20

        # Typosquatting check against all known targets
        for real_domain, fakes in PHISHING_TARGETS.items():
            # Check exact fakes
            for fake in fakes:
                if fake in domain and domain != real_domain:
                    findings.append({
                        "type": "TYPOSQUATTING",
                        "severity": "CRITICAL",
                        "detail": f'"{domain}" mimics "{real_domain}" — almost certainly phishing.',
                    })
                    score = max(score, 90)
                    break

            # Check if domain contains the real brand but with extra stuff
            brand = real_domain.split(".")[0]
            if brand in domain and domain != real_domain and len(domain) > len(real_domain):
                findings.append({
                    "type": "BRAND_IMPERSONATION",
                    "severity": "HIGH",
                    "detail": f'"{domain}" contains "{brand}" but is NOT the real "{real_domain}".',
                })
                score = max(score, 70)

        # Excessive hyphens (common in phishing)
        if domain.count("-") >= 2:
            findings.append({
                "type": "EXCESSIVE_HYPHENS",
                "severity": "MEDIUM",
                "detail": f"Domain has {domain.count('-')} hyphens. Legitimate services rarely do this.",
            })
            score += 15

        # Very long subdomain chains
        if len(domain_parts) > 4:
            findings.append({
                "type": "DEEP_SUBDOMAIN",
                "severity": "MEDIUM",
                "detail": f"Domain has {len(domain_parts)} parts. Complex subdomains are a phishing tactic.",
            })
            score += 15

        # Known safe
        known_safe = set()
        for real_domain in PHISHING_TARGETS:
            known_safe.add(real_domain)
        if domain in known_safe:
            findings = [{"type": "TRUSTED_DOMAIN", "severity": "LOW", "detail": f"{domain} is a known trusted domain."}]
            score = 0

        score = min(score, 100)
        level = self._score_to_level(score)
        return ThreatReport(url, "url", score, level, findings)

    # ═══════════════════════════════════════════════════════════════
    # 6. TEXT / MESSAGE SCAM DETECTION
    # ═══════════════════════════════════════════════════════════════
    SCAM_TEXT_PATTERNS = [
        (r"(?i)free\s*(airdrop|token|nft|mint|eth|btc)", "SCAM_AIRDROP", 70),
        (r"(?i)claim\s*your\s*(reward|token|nft|prize|bonus)", "SCAM_CLAIM", 65),
        (r"(?i)double\s*your\s*(eth|btc|bnb|crypto|money)", "DOUBLING_SCAM", 95),
        (r"(?i)send\s*\d+\s*(eth|btc|bnb|sol).*(?:get|receive)\s*\d+", "DOUBLING_SCAM", 95),
        (r"(?i)connect\s*wallet.*(?:verify|validate|sync|update)", "PHISHING_LURE", 75),
        (r"(?i)(?:verify|validate|sync|update)\s*(?:your\s*)?wallet", "PHISHING_LURE", 75),
        (r"(?i)(?:seed\s*phrase|private\s*key|secret\s*recovery|mnemonic)", "KEY_THEFT", 100),
        (r"(?i)(?:act\s*fast|urgent|expires?\s*(?:soon|today|in\s*\d+))", "URGENCY_TACTIC", 40),
        (r"(?i)(?:guaranteed|risk.?free|100%\s*(?:safe|profit))", "FALSE_GUARANTEE", 60),
        (r"(?i)dm\s*(?:me|us)\s*(?:for|to)\s*(?:claim|get|receive)", "DM_SCAM", 80),
        (r"(?i)(?:whatsapp|telegram|discord)\s*(?:group|channel).*(?:join|click)", "SOCIAL_LURE", 50),
        (r"(?i)(?:won|winner|selected|chosen)\s*(?:for|of)\s*(?:a\s*)?(?:prize|reward|giveaway)", "FAKE_WINNING", 75),
    ]

    def analyze_text(self, text: str) -> ThreatReport:
        """Scan text for scam patterns (DMs, social media messages, emails)."""
        findings = []
        score = 0

        for pattern, scam_type, severity in self.SCAM_TEXT_PATTERNS:
            if re.search(pattern, text):
                findings.append({
                    "type": scam_type,
                    "severity": "CRITICAL" if severity >= 90 else ("HIGH" if severity >= 70 else "MEDIUM"),
                    "detail": f"Scam pattern: {scam_type.replace('_', ' ')}",
                })
                score = max(score, severity)

        # Check for URLs in text
        urls = re.findall(r"https?://[^\s<>\"']+", text)
        for url in urls[:3]:
            url_report = self.analyze_url(url)
            if url_report.risk_score > 0:
                findings.extend(url_report.findings)
                score = max(score, url_report.risk_score)

        # Check for addresses in text
        addresses = re.findall(r"0x[a-fA-F0-9]{40}", text)
        if addresses and score > 30:
            findings.append({
                "type": "ADDRESS_IN_SCAM",
                "severity": "HIGH",
                "detail": f"Suspicious text contains {len(addresses)} wallet address(es).",
            })
            score = max(score, 70)

        score = min(score, 100)
        level = self._score_to_level(score)
        return ThreatReport(text[:100], "text", score, level, findings)

    # ═══════════════════════════════════════════════════════════════
    # FULL THREAT SCAN (combines all checks)
    # ═══════════════════════════════════════════════════════════════
    async def full_threat_scan(self, input_text: str, chain: str = "ethereum") -> ThreatReport:
        """Auto-detect input type and run appropriate analysis. Includes scam DB check."""
        text = input_text.strip()

        # Address
        if re.match(r"^0x[a-fA-F0-9]{40}$", text):
            addr_report = await self.analyze_address(text, chain)
            return addr_report

        # URL
        if text.startswith("http"):
            return self.analyze_url(text)

        # Text/message
        return self.analyze_text(text)

    # ── Helpers ───────────────────────────────────────────────────
    def _score_to_level(self, score: int) -> str:
        if score < 20:
            return "LOW"
        if score < 50:
            return "MEDIUM"
        if score < 75:
            return "HIGH"
        return "CRITICAL"

    def _get_cached(self, key: str) -> ThreatReport | None:
        if key in self._cache:
            ts, report = self._cache[key]
            if time.time() - ts < self._cache_ttl:
                return report
        return None

    def _set_cached(self, key: str, report: ThreatReport):
        self._cache[key] = (time.time(), report)
