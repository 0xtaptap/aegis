/**
 * Crypto Guardian - Background Service Worker
 * Handles phishing domain blocking and extension badge updates.
 */

// Phishing domain patterns (same as threat_intel.py)
const PHISHING_TARGETS = {
  'metamask.io': ['metamsk', 'metannask', 'netamask', 'metamaski', 'metam4sk', 'metamask-io'],
  'uniswap.org': ['uniiswap', 'uniswep', 'un1swap', 'uniswap-org', 'uniswapp'],
  'opensea.io': ['openseaa', 'opennsea', '0pensea', 'opensea-io', 'open-sea'],
  'pancakeswap.finance': ['pancakeswap-finance', 'pancakeswp', 'pancake-swap'],
  'aave.com': ['aave-com', 'aav3', 'aave-app'],
  'lido.fi': ['lido-fi', 'lid0', 'lido-app'],
  'safe.global': ['safe-global', 'gnosis-safe', 'safe-wallet'],
  'etherscan.io': ['etherscan-io', 'ether-scan', 'ethscan'],
  'coinbase.com': ['coinbase-com', 'c0inbase'],
  'binance.com': ['binance-com', 'b1nance', 'blnance'],
};

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.click', '.monster'];

function checkPhishing(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    const warnings = [];

    // Raw IP
    if (/^\d+\.\d+\.\d+\.\d+/.test(domain)) {
      warnings.push('Raw IP address URL - likely phishing');
    }

    // Suspicious TLD
    for (const tld of SUSPICIOUS_TLDS) {
      if (domain.endsWith(tld)) {
        warnings.push('Suspicious TLD: ' + tld);
        break;
      }
    }

    // Typosquatting check
    for (const [real, fakes] of Object.entries(PHISHING_TARGETS)) {
      for (const fake of fakes) {
        if (domain.includes(fake) && domain !== real) {
          warnings.push('PHISHING: "' + domain + '" mimics "' + real + '"');
        }
      }
      // Brand in wrong domain
      const brand = real.split('.')[0];
      if (domain.includes(brand) && domain !== real && domain.length > real.length) {
        warnings.push('Suspicious: contains "' + brand + '" but is NOT ' + real);
      }
    }

    return warnings;
  } catch (e) {
    return [];
  }
}

// Check every page load
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status === 'complete' && tab.url) {
    const warnings = checkPhishing(tab.url);
    if (warnings.length > 0) {
      // Set badge to warn
      chrome.action.setBadgeText({ tabId: tabId, text: '!' });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#ef4444' });

      // Show notification
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: showPhishingBanner,
        args: [warnings],
      }).catch(function() {});
    } else {
      chrome.action.setBadgeText({ tabId: tabId, text: '' });
    }
  }
});

// Phishing banner injected into the page
function showPhishingBanner(warnings) {
  const existing = document.getElementById('guardian-phishing-banner');
  if (existing) existing.remove();

  const banner = document.createElement('div');
  banner.id = 'guardian-phishing-banner';
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'width:100%', 'z-index:2147483647',
    'background:linear-gradient(135deg,#dc2626,#991b1b)', 'color:#fff',
    'padding:12px 20px', 'font-family:system-ui,sans-serif', 'font-size:14px',
    'display:flex', 'align-items:center', 'justify-content:space-between',
    'box-shadow:0 4px 20px rgba(220,38,38,0.5)',
  ].join(';');

  banner.innerHTML = ''
    + '<div style="display:flex;align-items:center;gap:8px;">'
    + '<span style="font-size:20px;">&#x1F6E1;&#xFE0F;</span>'
    + '<strong>Crypto Guardian:</strong>&nbsp;'
    + warnings.join(' | ')
    + '</div>'
    + '<button id="guardian-dismiss" style="background:none;border:1px solid #fff;color:#fff;'
    + 'padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;">Dismiss</button>';

  document.body.prepend(banner);
  document.getElementById('guardian-dismiss').addEventListener('click', function() {
    banner.remove();
  });
}

console.log('[Crypto Guardian] Background service worker active');
