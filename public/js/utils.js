// ═══════════════════════════════════════════════════════════════
// Utilities — Shared helpers for formatting, API calls, etc.
// ═══════════════════════════════════════════════════════════════

const Utils = {
  // ── Address formatting ─────────────────────────────────────
  shortenAddress(addr) {
    if (!addr) return '—';
    return addr.slice(0, 6) + '…' + addr.slice(-4);
  },

  // ── Validate Ethereum address ──────────────────────────────
  isValidAddress(addr) {
    return /^0x[a-fA-F0-9]{40}$/.test(addr);
  },

  // ── Relative time from ISO timestamp ───────────────────────
  timeAgo(timestamp) {
    if (!timestamp) return '—';
    const now = Date.now();
    const then = new Date(timestamp).getTime();
    const diff = Math.floor((now - then) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  },

  // ── Format large numbers ──────────────────────────────────
  formatAmount(amount) {
    if (amount === 'UNLIMITED') return '∞ UNLIMITED';
    const num = parseFloat(amount);
    if (isNaN(num)) return amount;
    if (num === 0) return '0';
    if (num < 0.0001) return '<0.0001';
    if (num < 1) return num.toFixed(4);
    if (num < 1000) return num.toFixed(2);
    if (num < 1000000) return (num / 1000).toFixed(1) + 'K';
    if (num < 1000000000) return (num / 1000000).toFixed(1) + 'M';
    return (num / 1000000000).toFixed(1) + 'B';
  },

  // ── API fetch wrapper ─────────────────────────────────────
  async apiFetch(url, options = {}) {
    try {
      const response = await fetch(url, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({ error: response.statusText }));
        throw new Error(err.error || `HTTP ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      console.error(`[API] ${url}:`, err);
      throw err;
    }
  },

  // ── Create DOM element ─────────────────────────────────────
  el(tag, attrs = {}, children = []) {
    const elem = document.createElement(tag);
    for (const [key, val] of Object.entries(attrs)) {
      if (key === 'className') elem.className = val;
      else if (key === 'textContent') elem.textContent = val;
      else if (key === 'innerHTML') elem.innerHTML = val;
      else if (key.startsWith('on')) elem.addEventListener(key.slice(2).toLowerCase(), val);
      else elem.setAttribute(key, val);
    }
    for (const child of children) {
      if (typeof child === 'string') elem.appendChild(document.createTextNode(child));
      else if (child) elem.appendChild(child);
    }
    return elem;
  },

  // ── Risk level color ───────────────────────────────────────
  riskColor(level) {
    const colors = {
      LOW: 'var(--accent-green)',
      MEDIUM: 'var(--accent-amber)',
      HIGH: 'var(--accent-red)',
      CRITICAL: 'var(--accent-red)',
    };
    return colors[level] || 'var(--text-secondary)';
  },

  // ── Escape HTML ────────────────────────────────────────────
  escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },

  // ── Get current time string ────────────────────────────────
  now() {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
  },
};

// Make globally available
window.Utils = Utils;
