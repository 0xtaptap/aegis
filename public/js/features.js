/* Crypto Guardian — Features JS (gas, token, bridge, wallets, export) */
/* 2026 Command Center Edition */

document.addEventListener('DOMContentLoaded', () => {

  // ═══════════════════════════════════════════════════════════
  // GAS TRACKER (F4) — powers both mini and full views
  // ═══════════════════════════════════════════════════════════
  const gasRefreshBtn = document.getElementById('gasRefreshBtn');
  const gasRefreshBtn2 = document.getElementById('gasRefreshBtn2');
  const gasMiniGrid = document.getElementById('gasMiniGrid');
  const gasFullGrid = document.getElementById('gasFullGrid');

  if (gasRefreshBtn) gasRefreshBtn.addEventListener('click', loadGasPrices);
  if (gasRefreshBtn2) gasRefreshBtn2.addEventListener('click', loadGasPrices);
  // Auto-load gas on page ready
  setTimeout(loadGasPrices, 1500);

  async function loadGasPrices() {
    if (gasMiniGrid) gasMiniGrid.innerHTML = '<div class="empty-state-sm">Loading…</div>';
    if (gasFullGrid) gasFullGrid.innerHTML = '<div class="empty-state-sm">Loading…</div>';
    try {
      const res = await fetch('/api/gas/compare');
      const data = await res.json();
      if (data.chains && data.chains.length) {
        // Mini grid (overview)
        if (gasMiniGrid) {
          gasMiniGrid.innerHTML = data.chains.map(c => {
            const gwei = c.gasGwei != null ? c.gasGwei.toFixed(1) : '—';
            const cls = c.gasGwei < 5 ? 'gas-low' : c.gasGwei < 30 ? 'gas-med' : 'gas-high';
            return `<div class="gas-mini">
              <span class="gas-mini-chain">${c.chain.toUpperCase().slice(0,5)}</span>
              <span class="gas-mini-val ${cls}">${gwei}</span>
            </div>`;
          }).join('');
        }
        // Full grid (gas tab)
        if (gasFullGrid) {
          gasFullGrid.innerHTML = data.chains.map(c => {
            const gwei = c.gasGwei != null ? c.gasGwei.toFixed(2) : '—';
            const cls = c.gasGwei < 5 ? 'gas-low' : c.gasGwei < 30 ? 'gas-med' : 'gas-high';
            const cheapest = c.chain === data.cheapest;
            return `<div class="gas-card-full">
              <div class="chain-name">${c.chain.toUpperCase()}</div>
              <div class="gas-val ${cls}">${gwei}</div>
              <div class="gas-unit">gwei</div>
              ${cheapest ? '<div class="gas-cheapest-tag">CHEAPEST</div>' : ''}
            </div>`;
          }).join('');
        }
      }
    } catch (e) {
      if (gasMiniGrid) gasMiniGrid.innerHTML = '<div class="empty-state-sm">Error</div>';
      if (gasFullGrid) gasFullGrid.innerHTML = '<div class="empty-state-sm">Error loading gas prices</div>';
    }
  }

  // ═══════════════════════════════════════════════════════════
  // TOKEN SCANNER (F10)
  // ═══════════════════════════════════════════════════════════
  const tokenCheckBtn = document.getElementById('tokenCheckBtn');
  const tokenInput = document.getElementById('tokenInput');
  const tokenChainSelect = document.getElementById('tokenChainSelect');
  const tokenResult = document.getElementById('tokenResult');

  if (tokenCheckBtn) {
    tokenCheckBtn.addEventListener('click', analyzeToken);
    tokenInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeToken(); });
  }

  async function analyzeToken() {
    const addr = tokenInput.value.trim();
    if (!addr || !addr.startsWith('0x')) {
      tokenResult.innerHTML = '<div class="result-error">Paste a valid token contract address</div>';
      return;
    }
    const chain = tokenChainSelect.value;
    tokenResult.innerHTML = '<div class="empty-state-sm">Analyzing: ownership, age, honeypot, holder concentration…</div>';
    tokenCheckBtn.disabled = true;
    try {
      const res = await fetch(`/api/token-security/${addr}/${chain}`);
      const data = await res.json();
      const color = data.riskLevel === 'CRITICAL' ? '#ff3366' : data.riskLevel === 'HIGH' ? '#ffb800' : data.riskLevel === 'MEDIUM' ? '#f0c040' : '#00ff88';
      let html = `<div class="token-verdict" style="border-left:4px solid ${color}; padding-left:14px; margin-bottom:14px">
        <div style="font-size:1.5em; font-weight:800; color:${color}">${data.riskLevel}</div>
        <div style="font-size:0.85em; color:var(--text-2)">Score: ${data.riskScore}/100</div>
      </div>`;
      if (data.findings && data.findings.length) {
        html += '<div class="token-findings">';
        data.findings.forEach(f => {
          const ic = f.severity === 'CRITICAL' ? '🚨' : f.severity === 'HIGH' ? '⚠️' : f.severity === 'MEDIUM' ? '⚡' : 'ℹ️';
          html += `<div class="finding-row finding-${f.severity.toLowerCase()}">
            <span class="finding-icon">${ic}</span>
            <span class="finding-type">${f.type}</span>
            <span class="finding-detail">${f.detail}</span>
          </div>`;
        });
        html += '</div>';
      }
      tokenResult.innerHTML = html;
    } catch (e) {
      tokenResult.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
    }
    tokenCheckBtn.disabled = false;
  }

  // ═══════════════════════════════════════════════════════════
  // BRIDGE FINDER (F5)
  // ═══════════════════════════════════════════════════════════
  const bridgeCheckBtn = document.getElementById('bridgeCheckBtn');
  const bridgeResult = document.getElementById('bridgeResult');

  if (bridgeCheckBtn) bridgeCheckBtn.addEventListener('click', findBridge);

  async function findBridge() {
    const from = document.getElementById('bridgeFrom').value;
    const to = document.getElementById('bridgeTo').value;
    const token = document.getElementById('bridgeToken').value;
    const amount = document.getElementById('bridgeAmount').value;
    if (from === to) {
      bridgeResult.innerHTML = '<div class="result-error">Source and destination must be different chains</div>';
      return;
    }
    bridgeResult.innerHTML = '<div class="empty-state-sm">Finding best route via Li.Fi…</div>';
    bridgeCheckBtn.disabled = true;
    try {
      const res = await fetch(`/api/bridge/quote?fromChain=${from}&toChain=${to}&token=${token}&amount=${amount}`);
      const data = await res.json();
      if (data.error) {
        bridgeResult.innerHTML = `<div class="result-error">${data.error}</div>`;
      } else if (data.route) {
        const r = data.route;
        bridgeResult.innerHTML = `<div class="bridge-route-result">
          <div class="route-header">
            <span class="route-from">${r.from.amount} ${r.from.token} on ${r.from.chain.toUpperCase()}</span>
            <span class="route-arrow">→</span>
            <span class="route-to">${r.to.amount} ${r.to.token} on ${r.to.chain.toUpperCase()}</span>
          </div>
          <div class="route-details">
            <div class="route-detail"><span>Bridge</span><strong>${r.bridge}</strong></div>
            <div class="route-detail"><span>Time</span><strong>${r.estimatedTime}</strong></div>
            <div class="route-detail"><span>Gas</span><strong>$${r.gasCostUsd}</strong></div>
            <div class="route-detail"><span>Fee</span><strong>$${r.bridgeFeeUsd}</strong></div>
            <div class="route-detail route-total"><span>Total Cost</span><strong>$${r.totalCostUsd}</strong></div>
          </div>
        </div>`;
      }
    } catch (e) {
      bridgeResult.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
    }
    bridgeCheckBtn.disabled = false;
  }

  // ═══════════════════════════════════════════════════════════
  // MULTI-WALLET (F7)
  // ═══════════════════════════════════════════════════════════
  const walletAddBtn = document.getElementById('walletAddBtn');
  const walletList = document.getElementById('walletList');

  if (walletAddBtn) walletAddBtn.addEventListener('click', addWallet);

  async function addWallet() {
    const addr = document.getElementById('walletAddInput').value.trim();
    const label = document.getElementById('walletLabelInput').value.trim();
    if (!addr || !addr.startsWith('0x')) return;
    try {
      await fetch('/api/wallets', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({address: addr, label: label})
      });
      document.getElementById('walletAddInput').value = '';
      document.getElementById('walletLabelInput').value = '';
      loadWallets();
    } catch (e) { console.error(e); }
  }

  async function loadWallets() {
    if (!walletList) return;
    try {
      const res = await fetch('/api/wallets');
      const data = await res.json();
      if (!data.wallets || !data.wallets.length) {
        walletList.innerHTML = '<div class="empty-state-sm">No wallets tracked yet</div>';
        return;
      }
      walletList.innerHTML = data.wallets.map(w => `
        <div class="wallet-item">
          <div class="wallet-info">
            <span class="wallet-addr">${w.address.slice(0,6)}…${w.address.slice(-4)}</span>
            ${w.label ? `<span class="wallet-label">${w.label}</span>` : ''}
          </div>
          <button class="remove-btn" onclick="removeWallet('${w.address}')">✕</button>
        </div>
      `).join('');
    } catch (e) {
      walletList.innerHTML = '<div class="empty-state-sm">Error loading wallets</div>';
    }
  }

  window.removeWallet = async function(addr) {
    try {
      await fetch(`/api/wallets/${addr}`, {method: 'DELETE'});
      loadWallets();
    } catch (e) { console.error(e); }
  };

  // ═══════════════════════════════════════════════════════════
  // TAX REPORT CENTER (F8 — Advanced)
  // ═══════════════════════════════════════════════════════════
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const exportSummaryBtn = document.getElementById('exportSummaryBtn');
  const exportGainsBtn = document.getElementById('exportGainsBtn');
  const exportIncomeBtn = document.getElementById('exportIncomeBtn');
  const exportHarvestBtn = document.getElementById('exportHarvestBtn');
  const exportSimulateBtn = document.getElementById('exportSimulateBtn');
  const exportResult = document.getElementById('exportResult');
  const exportResultCard = document.getElementById('exportResultCard');
  const exportResultTitle = document.getElementById('exportResultTitle');

  if (exportCsvBtn) exportCsvBtn.addEventListener('click', downloadCsv);
  if (exportSummaryBtn) exportSummaryBtn.addEventListener('click', showSummary);
  if (exportGainsBtn) exportGainsBtn.addEventListener('click', showCapitalGains);
  if (exportIncomeBtn) exportIncomeBtn.addEventListener('click', showIncomeReport);
  if (exportHarvestBtn) exportHarvestBtn.addEventListener('click', showHarvesting);
  if (exportSimulateBtn) exportSimulateBtn.addEventListener('click', showTaxSimulation);

  function showResultCard(title) {
    if (exportResultCard) exportResultCard.style.display = 'block';
    if (exportResultTitle) exportResultTitle.textContent = title;
  }

  function getExportAddr() {
    const addr = document.getElementById('exportAddressInput')?.value.trim();
    if (!addr || !addr.startsWith('0x')) {
      showResultCard('Error');
      exportResult.innerHTML = '<div class="result-error">Enter a valid 0x wallet address</div>';
      return null;
    }
    return addr;
  }

  async function fetchAndLog(addr) {
    const chains = ['ethereum', 'polygon', 'bsc', 'arbitrum', 'base', 'optimism', 'avalanche'];
    showResultCard('Fetching');
    exportResult.innerHTML = '<div class="empty-state-sm">Fetching transactions across 7 chains…</div>';
    let fetched = 0;
    for (const chain of chains) {
      try {
        await fetch(`/api/transactions/${addr}/${chain}`);
        fetched++;
        exportResult.innerHTML = `<div class="empty-state-sm">Fetched ${fetched}/7 chains…</div>`;
      } catch (e) { /* skip */ }
    }
    return fetched;
  }

  // ── Koinly CSV Download ──────────────────────────────────
  async function downloadCsv() {
    const addr = getExportAddr();
    if (!addr) return;
    exportCsvBtn.disabled = true;
    await fetchAndLog(addr);
    showResultCard('Koinly CSV Export');
    exportResult.innerHTML = '<div class="empty-state-sm">Generating Koinly Universal CSV…</div>';
    window.open(`/api/export/csv/${addr}`, '_blank');
    exportResult.innerHTML = '<div class="empty-state-sm" style="color:var(--green)">✓ CSV download started — import into Koinly, CoinTracker, or TurboTax</div>';
    exportCsvBtn.disabled = false;
  }

  // ── Enhanced Summary ─────────────────────────────────────
  async function showSummary() {
    const addr = getExportAddr();
    if (!addr) return;
    exportSummaryBtn.disabled = true;
    await fetchAndLog(addr);
    showResultCard('P&L Summary');
    exportResult.innerHTML = '<div class="empty-state-sm">Loading summary…</div>';
    try {
      const res = await fetch(`/api/export/summary/${addr}`);
      const data = await res.json();
      if (!data.tokens || !data.tokens.length) {
        exportResult.innerHTML = '<div class="empty-state-sm">No transactions found</div>';
        exportSummaryBtn.disabled = false;
        return;
      }
      let html = `<div style="display:flex;gap:16px;margin-bottom:14px;flex-wrap:wrap">
        <div class="rstat"><span class="rstat-val">${data.totalTransactions || 0}</span><span class="rstat-lbl">Total TXs</span></div>
        <div class="rstat"><span class="rstat-val">${data.totalTokens}</span><span class="rstat-lbl">Tokens</span></div>
        <div class="rstat"><span class="rstat-val">${(data.chainsUsed || []).length}</span><span class="rstat-lbl">Chains</span></div>
      </div>`;
      html += '<div class="summary-table"><table><thead><tr><th>Token</th><th>In</th><th>Out</th><th>Net</th><th>Income</th><th>Chains</th><th>TXs</th></tr></thead><tbody>';
      data.tokens.forEach(t => {
        const c = t.net >= 0 ? '#00ff88' : '#ff3366';
        const chains = (t.chains || []).map(ch => ch.slice(0,3).toUpperCase()).join(', ');
        const inc = t.incomeAmount > 0 ? `<span style="color:#ffb800">${t.incomeAmount}</span>` : '—';
        html += `<tr><td><strong>${t.token}</strong></td><td>${t.totalIn}</td><td>${t.totalOut}</td><td style="color:${c};font-weight:700">${t.net > 0 ? '+' : ''}${t.net}</td><td>${inc}</td><td style="font-size:0.65rem;color:var(--text-3)">${chains}</td><td>${t.txCount}</td></tr>`;
      });
      html += '</tbody></table></div>';
      exportResult.innerHTML = html;
    } catch (e) {
      exportResult.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
    }
    exportSummaryBtn.disabled = false;
  }

  // ── Capital Gains Report ─────────────────────────────────
  async function showCapitalGains() {
    const addr = getExportAddr();
    if (!addr) return;
    const method = document.getElementById('costBasisMethod')?.value || 'FIFO';
    exportGainsBtn.disabled = true;
    await fetchAndLog(addr);
    showResultCard(`Capital Gains (${method})`);
    exportResult.innerHTML = '<div class="empty-state-sm">Calculating gains with ' + method + ' method…</div>';
    try {
      const res = await fetch(`/api/export/gains/${addr}?method=${method}`);
      const data = await res.json();
      if (data.error) {
        exportResult.innerHTML = `<div class="result-error">${data.error}</div>`;
        exportGainsBtn.disabled = false;
        return;
      }

      const s = data.summary || {};
      let html = `<div style="display:flex;gap:14px;margin-bottom:14px;flex-wrap:wrap">
        <div class="rstat"><span class="rstat-val">${data.method}</span><span class="rstat-lbl">Method</span></div>
        <div class="rstat"><span class="rstat-val">${data.totalDisposals}</span><span class="rstat-lbl">Disposals</span></div>
        <div class="rstat"><span class="rstat-val" style="color:#ff3366">${s.shortTermDisposals || 0}</span><span class="rstat-lbl">Short Term</span></div>
        <div class="rstat"><span class="rstat-val" style="color:#00ff88">${s.longTermDisposals || 0}</span><span class="rstat-lbl">Long Term</span></div>
        <div class="rstat"><span class="rstat-val">${s.totalTokensTraded || 0}</span><span class="rstat-lbl">Tokens</span></div>
      </div>`;

      // Disposals table
      if (data.disposals && data.disposals.length) {
        html += '<div class="summary-table"><table><thead><tr><th>Token</th><th>Amount</th><th>Acquired</th><th>Disposed</th><th>Days Held</th><th>Term</th></tr></thead><tbody>';
        data.disposals.forEach(d => {
          const termColor = d.term === 'short' ? '#ff3366' : '#00ff88';
          const termLabel = d.term === 'short' ? 'SHORT' : 'LONG';
          html += `<tr><td><strong>${d.token}</strong></td><td>${d.amount}</td><td>${d.acquiredDate}</td><td>${d.disposedDate}</td><td>${d.holdingDays}</td><td style="color:${termColor};font-weight:700">${termLabel}</td></tr>`;
        });
        html += '</tbody></table></div>';
        if (data.totalDisposals > 200) {
          html += `<div class="empty-state-sm">Showing 200 of ${data.totalDisposals} disposals — download CSV for full report</div>`;
        }
      }

      // Unrealized holdings
      const unrealized = data.unrealized || {};
      const unrealizedKeys = Object.keys(unrealized);
      if (unrealizedKeys.length) {
        html += '<h4 style="margin-top:20px;margin-bottom:10px;color:var(--text-2)">Unrealized Holdings (Still Held)</h4>';
        html += '<div class="summary-table"><table><thead><tr><th>Token</th><th>Amount</th><th>Oldest Acquired</th><th>Days Held</th><th>Current Term</th></tr></thead><tbody>';
        unrealizedKeys.forEach(sym => {
          const u = unrealized[sym];
          const termColor = u.term === 'short' ? '#ffb800' : '#00ff88';
          html += `<tr><td><strong>${sym}</strong></td><td>${u.amount}</td><td>${u.oldestAcquired}</td><td>${u.holdingDays}</td><td style="color:${termColor}">${u.term.toUpperCase()}</td></tr>`;
        });
        html += '</tbody></table></div>';
      }

      exportResult.innerHTML = html;
    } catch (e) {
      exportResult.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
    }
    exportGainsBtn.disabled = false;
  }

  // ── Income Report ────────────────────────────────────────
  async function showIncomeReport() {
    const addr = getExportAddr();
    if (!addr) return;
    exportIncomeBtn.disabled = true;
    await fetchAndLog(addr);
    showResultCard('Income Report (DeFi / Staking / Airdrops)');
    exportResult.innerHTML = '<div class="empty-state-sm">Analyzing income events…</div>';
    try {
      const res = await fetch(`/api/export/income/${addr}`);
      const data = await res.json();

      let html = `<div style="display:flex;gap:14px;margin-bottom:14px;flex-wrap:wrap">
        <div class="rstat"><span class="rstat-val">${data.total || 0}</span><span class="rstat-lbl">Income Events</span></div>
      </div>`;

      // By type breakdown
      const byType = data.byType || {};
      const types = Object.keys(byType);
      if (types.length) {
        html += '<div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">';
        types.forEach(type => {
          const info = byType[type];
          const tokens = Object.entries(info.tokens || {}).map(([sym, amt]) => `${amt} ${sym}`).join(', ');
          html += `<div style="background:rgba(255,184,0,0.06);border:1px solid rgba(255,184,0,0.15);border-radius:8px;padding:12px 16px">
            <div style="font-weight:700;color:#ffb800;text-transform:uppercase;font-size:0.7rem">${type}</div>
            <div style="font-size:1.1rem;font-weight:700;color:var(--text-1)">${info.count} events</div>
            <div style="font-size:0.7rem;color:var(--text-3)">${tokens}</div>
          </div>`;
        });
        html += '</div>';
      }

      // Events table
      if (data.income && data.income.length) {
        html += '<div class="summary-table"><table><thead><tr><th>Date</th><th>Amount</th><th>Token</th><th>Type</th><th>Chain</th></tr></thead><tbody>';
        data.income.forEach(e => {
          html += `<tr><td>${e.date}</td><td style="color:#ffb800;font-weight:600">${e.amount}</td><td><strong>${e.token}</strong></td><td style="text-transform:capitalize">${e.type}</td><td>${e.chain}</td></tr>`;
        });
        html += '</tbody></table></div>';
      } else {
        html += '<div class="empty-state-sm">No income events found (staking, airdrops, mining, interest)</div>';
      }

      exportResult.innerHTML = html;
    } catch (e) {
      exportResult.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
    }
    exportIncomeBtn.disabled = false;
  }

  // ── Tax-Loss Harvesting ──────────────────────────────────
  async function showHarvesting() {
    const addr = getExportAddr();
    if (!addr) return;
    exportHarvestBtn.disabled = true;
    await fetchAndLog(addr);
    showResultCard('Tax-Loss Harvesting Suggestions');
    exportResult.innerHTML = '<div class="empty-state-sm">Finding harvestable positions…</div>';
    try {
      const res = await fetch(`/api/export/harvesting/${addr}`);
      const data = await res.json();

      let html = `<div style="display:flex;gap:14px;margin-bottom:14px;flex-wrap:wrap">
        <div class="rstat"><span class="rstat-val">${data.total || 0}</span><span class="rstat-lbl">Positions Held</span></div>
      </div>`;
      html += '<div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.12);border-radius:8px;padding:12px 16px;margin-bottom:14px;font-size:0.8rem;color:var(--text-2)">💡 <strong>Tax-loss harvesting</strong> = sell tokens at a loss to offset capital gains. Short-term losses offset income-tax-rate gains. Long-term losses offset lower capital-gains-rate. Consult a tax advisor.</div>';

      if (data.suggestions && data.suggestions.length) {
        html += '<div class="summary-table"><table><thead><tr><th>Token</th><th>Holding</th><th>Days Held</th><th>Term</th><th>Acquired</th><th>Note</th></tr></thead><tbody>';
        data.suggestions.forEach(s => {
          const termColor = s.term === 'short' ? '#ffb800' : '#00ff88';
          html += `<tr><td><strong>${s.token}</strong></td><td>${s.holdingAmount}</td><td>${s.holdingDays}</td><td style="color:${termColor};font-weight:700">${s.term.toUpperCase()}</td><td>${s.firstAcquired}</td><td style="font-size:0.7rem;color:var(--text-3)">${s.note}</td></tr>`;
        });
        html += '</tbody></table></div>';
      } else {
        html += '<div class="empty-state-sm">No positions found — scan wallets first to populate data</div>';
      }

      exportResult.innerHTML = html;
    } catch (e) {
      exportResult.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
    }
    exportHarvestBtn.disabled = false;
  }
  // ── Country Tax Simulation ────────────────────────────────
  async function showTaxSimulation() {
    const addr = getExportAddr();
    if (!addr) return;
    const country = document.getElementById('taxCountry')?.value || 'US';
    const income = parseFloat(document.getElementById('taxAnnualIncome')?.value) || 50000;
    exportSimulateBtn.disabled = true;
    await fetchAndLog(addr);
    const countryNames = {US:'United States',UK:'United Kingdom',IN:'India',DE:'Germany',AU:'Australia',CA:'Canada',FR:'France',JP:'Japan',KR:'South Korea',SG:'Singapore'};
    showResultCard(`🌍 Tax Simulation — ${countryNames[country] || country}`);
    exportResult.innerHTML = '<div class="empty-state-sm">Running tax simulation…</div>';
    try {
      const res = await fetch(`/api/export/simulate/${addr}?country=${country}&income=${income}`);
      const data = await res.json();
      if (data.error) {
        exportResult.innerHTML = `<div class="result-error">${data.error}</div>`;
        exportSimulateBtn.disabled = false;
        return;
      }

      let html = '';

      // Header stats
      html += `<div style="display:flex;gap:14px;margin-bottom:16px;flex-wrap:wrap">
        <div class="rstat"><span class="rstat-val">${data.countryName}</span><span class="rstat-lbl">${data.taxYear}</span></div>
        <div class="rstat"><span class="rstat-val">${data.costBasisMethod}</span><span class="rstat-lbl">Cost Basis</span></div>
        <div class="rstat"><span class="rstat-val">${data.totalDisposals}</span><span class="rstat-lbl">Disposals</span></div>
        <div class="rstat"><span class="rstat-val">${data.incomeEvents}</span><span class="rstat-lbl">Income Events</span></div>
      </div>`;

      // Method explanation
      html += `<div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.12);border-radius:8px;padding:12px 16px;margin-bottom:14px;font-size:0.8rem;color:var(--text-2)">📐 <strong>Cost Basis Method:</strong> ${data.methodExplanation}</div>`;

      // Capital gains breakdown
      const cg = data.capitalGains || {};
      if (Object.keys(cg).length) {
        html += '<h4 style="margin-bottom:10px;color:var(--text-2)">Capital Gains Tax</h4>';
        html += '<div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">';
        for (const [key, info] of Object.entries(cg)) {
          const isZero = info.taxRate === '0%';
          const borderColor = isZero ? 'rgba(0,255,136,0.2)' : 'rgba(255,51,102,0.15)';
          const bgColor = isZero ? 'rgba(0,255,136,0.04)' : 'rgba(255,51,102,0.04)';
          html += `<div style="background:${bgColor};border:1px solid ${borderColor};border-radius:8px;padding:12px 16px;flex:1;min-width:200px">
            <div style="font-weight:700;text-transform:uppercase;font-size:0.65rem;color:var(--text-3)">${key.replace(/([A-Z])/g,' $1').trim()}</div>
            <div style="font-size:1.4rem;font-weight:800;color:${isZero ? '#00ff88' : '#ff3366'}">${info.taxRate}</div>
            <div style="font-size:0.7rem;color:var(--text-3)">${info.disposals} disposals</div>
            <div style="font-size:0.7rem;color:var(--text-2);margin-top:4px">${info.rateNote}</div>
          </div>`;
        }
        html += '</div>';
      }

      // Income tax
      const it = data.incomeTax || {};
      if (it.events !== undefined) {
        html += `<div style="background:rgba(255,184,0,0.05);border:1px solid rgba(255,184,0,0.12);border-radius:8px;padding:12px 16px;margin-bottom:14px">
          <div style="font-weight:700;font-size:0.7rem;color:#ffb800">CRYPTO INCOME TAX</div>
          <div style="font-size:1.1rem;font-weight:700;color:var(--text-1)">${it.taxRate} on ${it.events} events</div>
          <div style="font-size:0.7rem;color:var(--text-3)">${it.note || ''}</div>
        </div>`;
      }

      // Exemptions
      const ex = data.exemptions || [];
      if (ex.length) {
        html += '<h4 style="margin-bottom:8px;color:var(--text-2)">Exemptions & Allowances</h4>';
        ex.forEach(e => {
          html += `<div style="background:rgba(0,255,136,0.04);border:1px solid rgba(0,255,136,0.12);border-radius:8px;padding:10px 14px;margin-bottom:8px">
            <strong style="color:#00ff88">${e.type}: ${e.amount}</strong>
            <div style="font-size:0.7rem;color:var(--text-3)">${e.note}</div>
          </div>`;
        });
      }

      // Tax breakdown table
      const bd = data.breakdown || [];
      if (bd.length) {
        html += '<h4 style="margin-top:14px;margin-bottom:8px;color:var(--text-2)">Full Breakdown</h4>';
        html += '<div class="summary-table"><table><thead><tr><th>Item</th><th>Rate</th><th>Events</th></tr></thead><tbody>';
        bd.forEach(b => {
          const rateColor = b.rate.includes('0%') && !b.rate.includes('10') ? '#00ff88' : 'var(--text-1)';
          html += `<tr><td>${b.item}</td><td style="color:${rateColor};font-weight:700">${b.rate}</td><td>${b.count}</td></tr>`;
        });
        html += '</tbody></table></div>';
      }

      // Required forms
      const forms = data.forms || [];
      if (forms.length) {
        html += `<div style="margin-top:14px;padding:10px 14px;background:rgba(255,255,255,0.02);border-radius:8px;border:1px solid rgba(255,255,255,0.06)">
          <strong style="font-size:0.7rem;color:var(--text-3)">REQUIRED FORMS:</strong>
          <div style="margin-top:4px;font-size:0.8rem;color:var(--text-2)">${forms.join(' • ')}</div>
        </div>`;
      }

      // Country notes
      const notes = data.notes || [];
      if (notes.length) {
        html += '<h4 style="margin-top:14px;margin-bottom:8px;color:var(--text-2)">Country-Specific Notes</h4>';
        notes.forEach(n => {
          html += `<div style="padding:6px 0;font-size:0.78rem;color:var(--text-2);border-bottom:1px solid rgba(255,255,255,0.03)">📌 ${n}</div>`;
        });
      }

      // Optimization tips
      const tips = data.optimizationTips || [];
      if (tips.length) {
        html += '<h4 style="margin-top:14px;margin-bottom:8px;color:#00d4ff">💡 Optimization Tips</h4>';
        tips.forEach(t => {
          html += `<div style="padding:6px 0;font-size:0.78rem;color:var(--text-2);border-bottom:1px solid rgba(0,212,255,0.06)">→ ${t}</div>`;
        });
      }

      // Disclaimer
      if (data.disclaimer) {
        html += `<div style="margin-top:16px;padding:10px 14px;background:rgba(255,51,102,0.04);border:1px solid rgba(255,51,102,0.12);border-radius:8px;font-size:0.7rem;color:#ff6688">⚠️ ${data.disclaimer}</div>`;
      }

      exportResult.innerHTML = html;
    } catch (e) {
      exportResult.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
    }
    exportSimulateBtn.disabled = false;
  }

  // Auto-load wallets
  setTimeout(loadWallets, 800);
});

// Global tab switch (called from HTML onclick)
window.switchTab = window.switchTab || function(tabId) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const tab = document.getElementById('tab-' + tabId);
  if (tab) tab.classList.add('active');
  const nav = document.querySelector(`[data-tab="${tabId}"]`);
  if (nav) nav.classList.add('active');
};
