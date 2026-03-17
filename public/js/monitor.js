// ═══════════════════════════════════════════════════════════════
// Monitor — Guardian mode + WebSocket alerts + action log
// ═══════════════════════════════════════════════════════════════

const Monitor = {
  ws: null,
  alerts: [],
  actionLog: [],

  // ── Initialize WebSocket connection ────────────────────────
  init() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws`;

    try {
      this.ws = new WebSocket(wsUrl);
      this.ws.onmessage = (event) => this._handleMessage(event);
      this.ws.onclose = () => {
        console.log('[WS] Disconnected, reconnecting in 5s…');
        setTimeout(() => this.init(), 5000);
      };
      this.ws.onerror = (err) => console.error('[WS] Error:', err);
    } catch (e) {
      console.warn('[WS] WebSocket not available:', e.message);
    }
  },

  // ── Handle incoming WebSocket messages ─────────────────────
  _handleMessage(event) {
    try {
      const data = JSON.parse(event.data);

      if (data.type === 'guardian_alert') {
        this.alerts.unshift(data.alert);
        if (this.alerts.length > 50) this.alerts = this.alerts.slice(0, 50);
        this.renderAlerts();
      }
    } catch (e) {
      console.error('[WS] Parse error:', e);
    }
  },

  // ── Toggle guardian mode ───────────────────────────────────
  async toggle(address, chains) {
    const statusEl = document.getElementById('monitorStatus');
    const dotEl = statusEl?.querySelector('.monitor-dot');
    const textEl = statusEl?.querySelector('span');

    const isActive = dotEl?.classList.contains('active');

    if (isActive) {
      await Utils.apiFetch('/api/guardian/stop', { method: 'POST' });
      dotEl?.classList.remove('active');
      dotEl?.classList.add('inactive');
      if (textEl) textEl.textContent = 'Inactive';
      this.addLog('Guardian Mode deactivated');
    } else {
      if (!address) return;
      await Utils.apiFetch('/api/guardian/start', {
        method: 'POST',
        body: JSON.stringify({ address, chains }),
      });
      dotEl?.classList.remove('inactive');
      dotEl?.classList.add('active');
      if (textEl) textEl.textContent = 'Active — Watching';
      this.addLog(`Guardian Mode activated for ${Utils.shortenAddress(address)}`);
    }

    return !isActive;
  },

  // ── Render alert feed ──────────────────────────────────────
  renderAlerts() {
    const container = document.getElementById('alertFeed');
    if (!container) return;

    if (this.alerts.length === 0) {
      container.innerHTML = '<div class="empty-state">No alerts yet</div>';
      return;
    }

    container.innerHTML = '';
    for (const alert of this.alerts.slice(0, 20)) {
      const severity = alert.severity === 'CRITICAL' ? 'critical' :
                       alert.severity === 'HIGH' ? 'warning' : 'info';
      const icon = severity === 'critical' ? '🚨' : severity === 'warning' ? '⚠️' : 'ℹ️';

      const item = Utils.el('div', { className: 'alert-item' }, [
        Utils.el('div', { className: `alert-icon ${severity}`, textContent: icon }),
        Utils.el('div', {
          className: 'alert-text',
          textContent: alert.message || alert.summary || `${alert.type} on ${alert.chain}`,
        }),
        Utils.el('span', {
          className: 'alert-time',
          textContent: Utils.timeAgo(alert.timestamp),
        }),
      ]);
      container.appendChild(item);
    }
  },

  // ── Action log ─────────────────────────────────────────────
  addLog(message) {
    this.actionLog.unshift({
      message,
      timestamp: new Date().toISOString(),
    });

    if (this.actionLog.length > 100) {
      this.actionLog = this.actionLog.slice(0, 100);
    }

    this.renderLog();
  },

  renderLog() {
    const container = document.getElementById('actionLog');
    const counter = document.getElementById('logCount');
    if (!container) return;

    if (counter) counter.textContent = this.actionLog.length;

    if (this.actionLog.length === 0) {
      container.innerHTML = '<div class="empty-state">No actions yet</div>';
      return;
    }

    container.innerHTML = '';
    for (const entry of this.actionLog.slice(0, 30)) {
      const item = Utils.el('div', { className: 'log-item' }, [
        document.createTextNode(entry.message),
        Utils.el('span', {
          className: 'log-time',
          textContent: Utils.timeAgo(entry.timestamp),
        }),
      ]);
      container.appendChild(item);
    }
  },
};

window.Monitor = Monitor;
