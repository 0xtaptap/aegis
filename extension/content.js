/**
 * Crypto Guardian — Content Script
 * Bridge between injected interceptor.js and the extension background.
 * Also renders the warning overlay when a risky tx is detected.
 */

// Inject the interceptor into the page context
const script = document.createElement('script');
script.src = chrome.runtime.getURL('interceptor.js');
script.onload = function() { this.remove(); };
(document.head || document.documentElement).appendChild(script);

// Listen for intercepted transactions from the page
window.addEventListener('message', function(event) {
  if (event.data && event.data.type === 'GUARDIAN_TX_INTERCEPT') {
    showWarningOverlay(event.data);
  }
});

// Warning overlay UI
function showWarningOverlay(data) {
  // Remove existing overlay if any
  const existing = document.getElementById('guardian-overlay');
  if (existing) existing.remove();

  const riskColors = {
    LOW: '#22c55e',
    MEDIUM: '#f59e0b',
    HIGH: '#ef4444',
    CRITICAL: '#dc2626',
  };

  const overlay = document.createElement('div');
  overlay.id = 'guardian-overlay';
  overlay.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'width:100%', 'height:100%',
    'background:rgba(0,0,0,0.85)', 'z-index:2147483647',
    'display:flex', 'align-items:center', 'justify-content:center',
    'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif',
  ].join(';');

  const borderColor = riskColors[data.riskLevel] || '#ef4444';

  overlay.innerHTML = ''
    + '<div style="background:#1a1a2e;border:2px solid ' + borderColor + ';border-radius:16px;'
    + 'padding:32px;max-width:480px;width:90%;color:#fff;box-shadow:0 0 60px ' + borderColor + '40;">'
    + '<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">'
    + '<div style="font-size:32px;">&#x1F6E1;&#xFE0F;</div>'
    + '<div>'
    + '<div style="font-size:20px;font-weight:700;">Crypto Guardian</div>'
    + '<div style="font-size:13px;color:#888;">Transaction Security Check</div>'
    + '</div>'
    + '</div>'
    + '<div style="background:' + borderColor + '20;border:1px solid ' + borderColor + ';'
    + 'border-radius:8px;padding:12px;margin-bottom:16px;">'
    + '<div style="font-size:14px;font-weight:600;color:' + borderColor + ';">'
    + 'Risk Level: ' + data.riskLevel + '</div>'
    + '<div style="font-size:12px;color:#ccc;margin-top:4px;">' + data.method + '</div>'
    + '</div>'
    + '<div style="margin-bottom:20px;">'
    + data.warnings.map(function(w) {
        return '<div style="display:flex;gap:8px;padding:8px 0;border-bottom:1px solid #333;">'
          + '<span style="color:' + borderColor + ';">&#x26A0;</span>'
          + '<span style="font-size:13px;color:#ddd;">' + w + '</span></div>';
      }).join('')
    + '</div>'
    + '<div style="display:flex;gap:12px;">'
    + '<button id="guardian-reject" style="flex:1;padding:12px;border-radius:8px;border:none;'
    + 'background:#ef4444;color:#fff;font-weight:600;font-size:14px;cursor:pointer;">'
    + 'REJECT</button>'
    + '<button id="guardian-approve" style="flex:1;padding:12px;border-radius:8px;border:none;'
    + 'background:#333;color:#fff;font-weight:600;font-size:14px;cursor:pointer;">'
    + 'Proceed Anyway</button>'
    + '</div>'
    + '<div style="text-align:center;margin-top:12px;font-size:11px;color:#666;">'
    + 'Auto-rejecting in 30 seconds for your safety</div>'
    + '</div>';

  document.body.appendChild(overlay);

  // Button handlers
  document.getElementById('guardian-reject').addEventListener('click', function() {
    window.postMessage({ type: 'GUARDIAN_TX_DECISION', approved: false }, '*');
    overlay.remove();
  });

  document.getElementById('guardian-approve').addEventListener('click', function() {
    window.postMessage({ type: 'GUARDIAN_TX_DECISION', approved: true }, '*');
    overlay.remove();
  });
}
