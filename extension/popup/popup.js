/**
 * Crypto Guardian - Popup Script
 * Quick scan from the extension popup.
 */

const API = 'http://localhost:3000';

document.getElementById('scanBtn').addEventListener('click', scan);
document.getElementById('scanInput').addEventListener('keypress', function(e) {
  if (e.key === 'Enter') scan();
});

// Load stats from storage
chrome.storage.local.get(['blocked', 'scanned'], function(data) {
  document.getElementById('blockedCount').textContent = data.blocked || 0;
  document.getElementById('scannedCount').textContent = data.scanned || 0;
});

async function scan() {
  const input = document.getElementById('scanInput').value.trim();
  if (!input) return;

  const resultDiv = document.getElementById('result');
  resultDiv.style.display = 'block';
  resultDiv.innerHTML = '<div class="loading">Scanning...</div>';

  // Increment scan count
  chrome.storage.local.get(['scanned'], function(data) {
    chrome.storage.local.set({ scanned: (data.scanned || 0) + 1 });
    document.getElementById('scannedCount').textContent = (data.scanned || 0) + 1;
  });

  // Detect input type
  const isAddress = /^0x[a-fA-F0-9]{40}$/.test(input);
  const isUrl = input.startsWith('http');

  try {
    let result;

    if (isAddress) {
      // Contract risk check
      const resp = await fetch(API + '/api/contract-risk/' + input + '/ethereum');
      result = await resp.json();
    } else {
      // Use chat endpoint for URL/text analysis
      const resp = await fetch(API + '/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'Check if this is safe: ' + input,
          session_id: 'extension',
        }),
      });
      result = await resp.json();
      // Display as text result
      resultDiv.innerHTML = '<div class="result-card">'
        + '<div style="font-size:13px;color:#ddd;">' + (result.reply || result.message || JSON.stringify(result)) + '</div>'
        + '</div>';
      return;
    }

    // Display contract risk result
    const score = result.riskScore || 0;
    const level = result.riskLevel || 'UNKNOWN';
    const scoreColor = score < 20 ? '#22c55e' : (score < 50 ? '#f59e0b' : '#ef4444');
    const cardClass = score > 50 ? 'danger' : 'safe';

    let findingsHtml = '';
    if (result.findings && result.findings.length > 0) {
      findingsHtml = '<div class="findings">'
        + result.findings.map(function(f) {
            const sev = (f.severity || 'LOW').toLowerCase();
            return '<div class="finding-item">'
              + '<div class="dot ' + sev + '"></div>'
              + '<span>' + (f.detail || f.type) + '</span></div>';
          }).join('')
        + '</div>';
    }

    resultDiv.innerHTML = ''
      + '<div class="result-card ' + cardClass + '">'
      + '<div style="display:flex;justify-content:space-between;align-items:center;">'
      + '<div>'
      + '<div style="font-size:12px;color:#888;">Risk Score</div>'
      + '<div class="score" style="color:' + scoreColor + ';">' + score + '/100</div>'
      + '</div>'
      + '<div style="text-align:right;">'
      + '<div style="font-size:12px;color:#888;">Level</div>'
      + '<div style="font-size:16px;font-weight:600;color:' + scoreColor + ';">' + level + '</div>'
      + '</div>'
      + '</div>'
      + findingsHtml
      + '</div>';

    if (score > 50) {
      chrome.storage.local.get(['blocked'], function(data) {
        chrome.storage.local.set({ blocked: (data.blocked || 0) + 1 });
        document.getElementById('blockedCount').textContent = (data.blocked || 0) + 1;
      });
    }
  } catch (e) {
    resultDiv.innerHTML = '<div class="result-card danger">'
      + '<div style="font-size:13px;color:#ef4444;">Could not reach Guardian backend at ' + API + '</div>'
      + '<div style="font-size:11px;color:#888;margin-top:4px;">Make sure the server is running.</div>'
      + '</div>';
  }
}
