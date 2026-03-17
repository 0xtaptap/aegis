// ═══════════════════════════════════════════════════════════════
// Risk — Animated risk gauge and score display
// ═══════════════════════════════════════════════════════════════

const Risk = {
  // ── Update the SVG risk gauge ──────────────────────────────
  updateGauge(score, level) {
    const fill = document.getElementById('gaugeFill');
    const text = document.getElementById('gaugeScore');
    const label = document.getElementById('gaugeLabel');
    const badge = document.getElementById('riskBadge');

    if (!fill || !text || !label) return;

    // Animate score number
    this._animateNumber(text, score);

    // Gauge fill (circumference = 2πr = 2π*85 ≈ 534)
    const circumference = 534;
    const offset = circumference - (score / 100) * circumference;
    fill.style.strokeDashoffset = offset;

    // Color based on level
    const colorMap = {
      LOW: 'var(--accent-green)',
      MEDIUM: 'var(--accent-amber)',
      HIGH: 'var(--accent-red)',
      CRITICAL: 'var(--accent-red)',
    };
    fill.style.stroke = colorMap[level] || colorMap.LOW;
    text.style.fill = colorMap[level] || colorMap.LOW;

    // Label
    label.textContent = level || '—';

    // Badge
    if (badge) {
      badge.textContent = level;
      badge.style.background = `${colorMap[level]}20`;
      badge.style.color = colorMap[level];
    }
  },

  // ── Update breakdown stats ─────────────────────────────────
  updateBreakdown(data) {
    const ids = {
      statApprovals: data.totalApprovals ?? '—',
      statUnlimited: data.unlimitedApprovals ?? '—',
      statStale: data.staleApprovals ?? '—',
      statTxs: data.totalTransactions ?? '—',
    };

    for (const [id, value] of Object.entries(ids)) {
      const el = document.getElementById(id);
      if (el) this._animateNumber(el, value);
    }
  },

  // ── Animated number counter ────────────────────────────────
  _animateNumber(element, target) {
    if (typeof target !== 'number' || isNaN(target)) {
      element.textContent = target;
      return;
    }

    const duration = 1200;
    const startTime = performance.now();
    const startValue = parseInt(element.textContent) || 0;

    function step(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);

      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(startValue + (target - startValue) * eased);

      element.textContent = current;

      if (progress < 1) {
        requestAnimationFrame(step);
      }
    }

    requestAnimationFrame(step);
  },

  // ── Reset gauge to default ─────────────────────────────────
  reset() {
    const fill = document.getElementById('gaugeFill');
    const text = document.getElementById('gaugeScore');
    const label = document.getElementById('gaugeLabel');

    if (fill) fill.style.strokeDashoffset = '534';
    if (text) text.textContent = '—';
    if (label) label.textContent = 'Scanning…';
  },
};

window.Risk = Risk;
