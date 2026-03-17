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
    Monitor.addLog('Crypto Guardian initialized — READ-ONLY mode');

    // Wire up scan button
    document.getElementById('scanBtn').addEventListener('click', () => this.scan());

    // Wire up wallet input (Enter key)
    document.getElementById('walletInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.scan();
    });

    // Wire up chain selector
    document.querySelectorAll('.chain-btn').forEach(btn => {
      btn.addEventListener('click', () => this.selectChain(btn));
    });

    // Wire up guardian toggle
    document.getElementById('guardianToggle').addEventListener('click', () => this.toggleGuardian());

    // Wire up phishing checker
    document.getElementById('phishingCheckBtn').addEventListener('click', () => this.checkPhishing());
    document.getElementById('phishingInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.checkPhishing();
    });

    console.log('🛡️ Crypto Guardian ready');
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
    this.showLoading('Scanning blockchain…');
    this.showDashboard();
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

      // Update counts and portfolio value
      document.getElementById('approvalCount').textContent = allApprovals.length;
      document.getElementById('txCount').textContent = allTransactions.length;
      
      let totalPortfolioValue = 0;
      for (const b of allBalances) {
        totalPortfolioValue += (b.valueUsd || 0);
      }
      const portfolioEl = document.getElementById('statPortfolio');
      if (portfolioEl) {
          portfolioEl.textContent = totalPortfolioValue > 0 ? `$${totalPortfolioValue.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}` : '$0.00';
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
        const unlim = allApprovals.filter(a => a.isUnlimited).length;
        const stale = allApprovals.filter(a => a.ageInDays > 180).length;
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
      // Error boundary: show user-visible error notification
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
    const toggle = document.getElementById('toggleSwitch');

    if (!this.currentAddress) {
      Chat.addMessage('assistant', '⚠️ Please scan a wallet first before enabling Guardian Mode.');
      Chat.toggle();
      return;
    }

    const chains = this.currentChain === 'all' ? this.allChains : [this.currentChain];
    const isNowActive = await Monitor.toggle(this.currentAddress, chains);
    toggle.classList.toggle('active', isNowActive);
  },

  // ── Dashboard visibility ───────────────────────────────────
  showDashboard() {
    document.getElementById('dashboard').style.display = 'grid';
  },

  // ── Loading states ─────────────────────────────────────────
  showLoading(text) {
    document.getElementById('loadingOverlay').style.display = 'flex';
    document.getElementById('loadingText').textContent = text || 'Loading…';
  },

  updateLoadingText(text) {
    document.getElementById('loadingText').textContent = text;
  },

  hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
  },
};

// ── Boot on DOM ready ────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => App.init());
