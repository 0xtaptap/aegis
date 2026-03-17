// ═══════════════════════════════════════════════════════════════
// App — Main controller for Crypto Guardian Dashboard
// Wires up all modules and handles the scan workflow
// ═══════════════════════════════════════════════════════════════

const App = {
  currentAddress: null,
  currentChain: 'ethereum',
  allChains: ['ethereum', 'polygon', 'bsc', 'arbitrum', 'base', 'optimism', 'avalanche'],

  // ── Boot the application ───────────────────────────────────
  init() {
    // Initialize modules
    Chat.init();
    Monitor.init();
    Monitor.addLog('Crypto Guardian initialized — AUTONOMOUS mode');

    // Wire up scan button
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) scanBtn.addEventListener('click', () => this.scan());

    // Wire up wallet input (Enter key)
    const walletInput = document.getElementById('walletInput');
    if (walletInput) walletInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.scan();
    });

    // Wire up chain selector (dropdown)
    const chainSelect = document.getElementById('chainSelect');
    if (chainSelect) chainSelect.addEventListener('change', (e) => {
      this.currentChain = e.target.value;
    });

    // Wire up chain buttons (if any)
    document.querySelectorAll('.chain-btn').forEach(btn => {
      btn.addEventListener('click', () => this.selectChain(btn));
    });

    // Wire up guardian toggle
    const guardianToggle = document.getElementById('guardianToggle');
    if (guardianToggle) guardianToggle.addEventListener('click', () => this.toggleGuardian());

    // Wire up phishing checker
    const phishingCheckBtn = document.getElementById('phishingCheckBtn');
    if (phishingCheckBtn) phishingCheckBtn.addEventListener('click', () => this.checkPhishing());
    const phishingInput = document.getElementById('phishingInput');
    if (phishingInput) phishingInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.checkPhishing();
    });

    console.log('🛡️ Crypto Guardian ready — 21 tools, autonomous mode');
  },

  // ── Chain selection ────────────────────────────────────────
  selectChain(btn) {
    document.querySelectorAll('.chain-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    this.currentChain = btn.dataset.chain;
  },

  // ── Main scan workflow ─────────────────────────────────────
  async scan() {
    const input = document.getElementById('walletInput');
    const address = input.value.trim();

    if (!Utils.isValidAddress(address)) {
      input.style.borderColor = 'var(--accent-red)';
      input.style.boxShadow = '0 0 0 3px rgba(255, 51, 102, 0.15)';
      setTimeout(() => {
        input.style.borderColor = '';
        input.style.boxShadow = '';
      }, 2000);
      return;
    }

    this.currentAddress = address;
    this.currentChain = document.getElementById('chainSelect')?.value || this.currentChain;
    this.showLoading('Scanning blockchain…');
    Risk.reset();
    Monitor.addLog(`Scanning ${Utils.shortenAddress(address)} on ${this.currentChain === 'all' ? 'all chains' : this.currentChain}`);

    const chains = this.currentChain === 'all' ? this.allChains : [this.currentChain];

    try {
      // Run all scans in parallel
      const results = await Promise.allSettled(
        chains.map(chain => Utils.apiFetch(`/api/scan/${address}/${chain}`))
      );

      // Merge results across chains
      let allApprovals = [];
      let allTransactions = [];
      let allBalances = [];
      let allNftApprovals = [];
      let totalNfts = 0;

      for (const result of results) {
        if (result.status === 'fulfilled') {
          const data = result.value;
          allApprovals = allApprovals.concat(data.approvals || []);
          allTransactions = allTransactions.concat(data.transactions || []);
          allBalances = allBalances.concat(data.balances || []);
          allNftApprovals = allNftApprovals.concat(data.nftApprovals || []);
          totalNfts += (data.nfts || []).length;
        }
      }

      // Sort transactions by block number (newest first)
      allTransactions.sort((a, b) => (b.blockNumber || 0) - (a.blockNumber || 0));

      // Render sections
      Scanner.renderApprovals(allApprovals, document.getElementById('approvalsTable'));
      Scanner.renderTransactions(allTransactions.slice(0, 30), document.getElementById('txList'));
      Scanner.renderRevokeList(allApprovals, document.getElementById('revokeList'));

      // Update counts and portfolio value (null-safe)
      const approvalCountEl = document.getElementById('approvalCount');
      if (approvalCountEl) approvalCountEl.textContent = allApprovals.length;
      const txCountEl = document.getElementById('txCount');
      if (txCountEl) txCountEl.textContent = allTransactions.length;
      const statTxsEl = document.getElementById('statTxs');
      if (statTxsEl) statTxsEl.textContent = allTransactions.length;
      const statApprovalsEl = document.getElementById('statApprovals');
      if (statApprovalsEl) statApprovalsEl.textContent = allApprovals.length;

      // Unlimited & stale counts
      const unlim = allApprovals.filter(a => a.isUnlimited).length;
      const stale = allApprovals.filter(a => a.ageInDays > 180).length;
      const statUnlimitedEl = document.getElementById('statUnlimited');
      if (statUnlimitedEl) statUnlimitedEl.textContent = unlim;
      const statStaleEl = document.getElementById('statStale');
      if (statStaleEl) statStaleEl.textContent = stale;

      let totalPortfolioValue = 0;
      for (const b of allBalances) {
        totalPortfolioValue += (b.valueUsd || 0);
      }
      const portfolioEl = document.getElementById('statPortfolio');
      if (portfolioEl) {
        portfolioEl.textContent = totalPortfolioValue > 0
          ? `$${totalPortfolioValue.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}`
          : '$0.00';
      }

      // Fetch risk score
      this.updateLoadingText('Calculating risk score…');
      try {
        const riskData = await Utils.apiFetch(`/api/risk/${address}`);
        Risk.updateGauge(riskData.score, riskData.level);
        Risk.updateBreakdown(riskData);
        Monitor.addLog(`Risk score: ${riskData.score}/100 (${riskData.level})`);
      } catch (e) {
        // Calculate local risk from approval data
        const score = Math.min(unlim * 15 + stale * 5, 100);
        const level = score < 20 ? 'LOW' : score < 50 ? 'MEDIUM' : score < 75 ? 'HIGH' : 'CRITICAL';
        Risk.updateGauge(score, level);
        Risk.updateBreakdown({
          totalApprovals: allApprovals.length,
          unlimitedApprovals: unlim,
          staleApprovals: stale,
          totalTransactions: allTransactions.length,
        });
      }

      Monitor.addLog(`Scan complete: ${allApprovals.length} approvals, ${allTransactions.length} transactions`);

    } catch (err) {
      console.error('[Scan] Error:', err);
      Monitor.addLog(`Scan error: ${err.message}`);
      const container = document.getElementById('approvalsTable');
      if (container) {
        container.innerHTML = `<div style="color:var(--accent-red);padding:1rem;text-align:center;">
          ⚠️ Scan failed: ${err.message || 'Network error'}. Please try again.</div>`;
      }
    }

    this.hideLoading();
  },

  // ── Phishing checker ───────────────────────────────────────
  async checkPhishing() {
    const input = document.getElementById('phishingInput');
    const resultDiv = document.getElementById('phishingResult');
    const value = input.value.trim();

    if (!value) return;

    try {
      const result = await Utils.apiFetch('/api/phishing/check', {
        method: 'POST',
        body: JSON.stringify({ input: value }),
      });

      resultDiv.className = 'phishing-result visible ' +
        (result.verdict === 'SAFE' || result.verdict === 'safe' ? 'safe' :
         result.verdict === 'CAUTION' ? 'caution' : 'danger');

      let html = `<strong>${result.verdict}</strong> — Risk Score: ${result.score}/100<br>`;
      if (result.risks && result.risks.length > 0) {
        html += '<br>';
        for (const risk of result.risks) {
          const icon = risk.severity > 60 ? '🚨' : risk.severity > 30 ? '⚠️' : 'ℹ️';
          html += `${icon} ${Utils.escapeHtml(risk.detail)}<br>`;
        }
      }
      if (result.recommendation) {
        html += `<br><em>${Utils.escapeHtml(result.recommendation)}</em>`;
      }

      resultDiv.innerHTML = html;
      Monitor.addLog(`Phishing check: "${value.slice(0, 30)}…" → ${result.verdict}`);

    } catch (err) {
      resultDiv.className = 'phishing-result visible danger';
      resultDiv.innerHTML = `⚠️ Check failed: ${Utils.escapeHtml(err.message)}`;
    }
  },

  // ── Guardian toggle ────────────────────────────────────────
  async toggleGuardian() {
    const toggle = document.getElementById('guardianToggle');

    if (!this.currentAddress) {
      Chat.addMessage('assistant', '⚠️ Please scan a wallet first before enabling Guardian Mode.');
      return;
    }

    const chains = this.currentChain === 'all' ? this.allChains : [this.currentChain];
    const isNowActive = await Monitor.toggle(this.currentAddress, chains);
    if (toggle) toggle.classList.toggle('active', isNowActive);
  },

  // ── Loading states ─────────────────────────────────────────
  showLoading(text) {
    const overlay = document.getElementById('loadingOverlay');
    const textEl = document.getElementById('loadingText');
    if (overlay) overlay.style.display = 'flex';
    if (textEl) textEl.textContent = text || 'Loading…';
  },

  updateLoadingText(text) {
    const textEl = document.getElementById('loadingText');
    if (textEl) textEl.textContent = text;
  },

  hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.style.display = 'none';
  },
};

// ── Boot on DOM ready ────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => App.init());
