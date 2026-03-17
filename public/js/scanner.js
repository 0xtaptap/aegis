// ═══════════════════════════════════════════════════════════════
// Scanner — Approval Scanner + Transaction Feed rendering
// ═══════════════════════════════════════════════════════════════

const Scanner = {
  // ── Render approval table ──────────────────────────────────
  renderApprovals(approvals, container) {
    container.innerHTML = '';

    if (!approvals || approvals.length === 0) {
      container.innerHTML = '<div class="empty-state">✅ No active approvals found — clean!</div>';
      return;
    }

    // Header row
    const header = Utils.el('div', { className: 'approval-row header' }, [
      Utils.el('span', { textContent: 'Token' }),
      Utils.el('span', { textContent: 'Spender' }),
      Utils.el('span', { textContent: 'Allowance' }),
      Utils.el('span', { textContent: 'Age' }),
      Utils.el('span', { textContent: 'Risk' }),
    ]);
    container.appendChild(header);

    // Data rows
    for (const approval of approvals) {
      const row = Utils.el('div', { className: 'approval-row' }, [
        Utils.el('span', {
          innerHTML: `<strong>${Utils.escapeHtml(approval.tokenName || '??')}</strong>`,
          title: approval.token,
        }),
        Utils.el('span', {
          className: 'mono-text',
          textContent: approval.spenderLabel || Utils.shortenAddress(approval.spender),
          title: approval.spender,
          style: `font-family: var(--font-mono); font-size: 0.78rem; ${approval.isKnownProtocol ? 'color: var(--accent-green);' : 'color: var(--accent-amber);'}`,
        }),
        Utils.el('span', {
          textContent: Utils.formatAmount(approval.amount),
          style: approval.isUnlimited ? 'color: var(--accent-red); font-weight: 700;' : '',
        }),
        Utils.el('span', {
          textContent: approval.ageInDays != null ? `${approval.ageInDays}d` : '—',
          style: approval.ageInDays > 180 ? 'color: var(--accent-amber);' : '',
        }),
        Utils.el('span', {
          className: `risk-tag ${approval.riskLevel?.toLowerCase() || 'low'}`,
          textContent: approval.riskLevel || 'LOW',
        }),
      ]);
      container.appendChild(row);
    }
  },

  // ── Render transaction feed ────────────────────────────────
  renderTransactions(transactions, container) {
    container.innerHTML = '';

    if (!transactions || transactions.length === 0) {
      container.innerHTML = '<div class="empty-state">No recent transactions</div>';
      return;
    }

    for (const tx of transactions) {
      const item = Utils.el('div', { className: 'tx-item' }, [
        Utils.el('div', {
          className: `tx-dir ${tx.direction?.toLowerCase() || 'in'}`,
          textContent: tx.direction === 'OUT' ? '↑' : '↓',
        }),
        Utils.el('div', { className: 'tx-info' }, [
          Utils.el('div', {
            className: 'tx-summary',
            textContent: tx.summary || `${tx.direction} ${tx.value} ${tx.asset}`,
          }),
          Utils.el('div', {
            className: 'tx-meta',
            textContent: `${Utils.shortenAddress(tx.hash)} · ${Utils.timeAgo(tx.timestamp)}`,
          }),
        ]),
        Utils.el('div', {
          className: 'tx-value',
          textContent: `${tx.direction === 'OUT' ? '-' : '+'}${Utils.formatAmount(tx.value)} ${tx.asset || ''}`,
          style: `color: ${tx.direction === 'OUT' ? 'var(--accent-red)' : 'var(--accent-green)'}`,
        }),
      ]);

      container.appendChild(item);
    }
  },

  // ── Render revoke recommendations ──────────────────────────
  renderRevokeList(approvals, container) {
    container.innerHTML = '';

    const risky = (approvals || []).filter(a =>
      a.isUnlimited || a.riskLevel === 'HIGH' || a.riskLevel === 'MEDIUM'
    );

    if (risky.length === 0) {
      container.innerHTML = '<div class="empty-state">✅ No risky approvals to revoke</div>';
      return;
    }

    for (const approval of risky) {
      const item = Utils.el('div', { className: 'revoke-item' }, [
        Utils.el('div', { className: 'token-name', textContent: `${approval.tokenName} → ${Utils.shortenAddress(approval.spender)}` }),
        Utils.el('div', {
          className: 'revoke-reason',
          textContent: approval.isUnlimited
            ? '⚠️ UNLIMITED — can drain all tokens'
            : `⚠️ Stale approval (${approval.ageInDays}d old)`,
        }),
        Utils.el('div', {
          className: 'revoke-action',
          textContent: `→ Call approve(${Utils.shortenAddress(approval.spender)}, 0) on ${Utils.shortenAddress(approval.token)}`,
        }),
      ]);
      container.appendChild(item);
    }
  },
};

window.Scanner = Scanner;
