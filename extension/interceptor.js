/**
 * Crypto Guardian — Transaction Interceptor
 * Injected into dApp pages via content script.
 * Hooks window.ethereum to intercept eth_sendTransaction and eth_signTypedData.
 * Shows a warning before the user signs anything dangerous.
 */

(function() {
  'use strict';

  // Don't run if no wallet provider
  if (!window.ethereum) return;

  const GUARDIAN_API = 'http://localhost:3000';
  const originalRequest = window.ethereum.request.bind(window.ethereum);

  // Methods we intercept
  const DANGEROUS_METHODS = [
    'eth_sendTransaction',
    'eth_signTypedData',
    'eth_signTypedData_v3',
    'eth_signTypedData_v4',
    'personal_sign',
    'eth_sign',
  ];

  // Known approve selectors
  const APPROVE_SELECTOR = '0x095ea7b3';
  const SET_APPROVAL_FOR_ALL = '0xa22cb465';
  const INFINITE_APPROVAL = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

  window.ethereum.request = async function(args) {
    const method = args.method;

    // Only intercept dangerous methods
    if (!DANGEROUS_METHODS.includes(method)) {
      return originalRequest(args);
    }

    try {
      const params = args.params || [];
      let riskLevel = 'LOW';
      let warnings = [];

      if (method === 'eth_sendTransaction' && params[0]) {
        const tx = params[0];
        const data = (tx.data || '').toLowerCase();

        // Check for infinite approval
        if (data.startsWith(APPROVE_SELECTOR.slice(2)) && data.includes(INFINITE_APPROVAL)) {
          riskLevel = 'CRITICAL';
          warnings.push('UNLIMITED token approval detected! This allows the spender to drain ALL your tokens.');
        }

        // Check for setApprovalForAll(operator, true)
        if (data.startsWith(SET_APPROVAL_FOR_ALL.slice(2))) {
          const boolValue = data.slice(-64);
          if (boolValue.includes('1')) {
            riskLevel = 'HIGH';
            warnings.push('NFT setApprovalForAll detected. This gives full access to ALL your NFTs in this collection.');
          }
        }

        // Check for ETH transfer to unknown contract
        const value = parseInt(tx.value || '0x0', 16);
        if (value > 0) {
          const ethAmount = value / 1e18;
          if (ethAmount > 0.1) {
            warnings.push('Sending ' + ethAmount.toFixed(4) + ' ETH. Make sure you trust the recipient.');
          }
        }

        // Try to get simulation from our backend
        try {
          const simResponse = await fetch(GUARDIAN_API + '/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tx: tx, chain: 'ethereum' }),
          });
          if (simResponse.ok) {
            const simData = await simResponse.json();
            if (simData.error) {
              riskLevel = 'HIGH';
              warnings.push('Transaction simulation FAILED: ' + (simData.error.message || 'Unknown error'));
            }
          }
        } catch (e) {
          // Backend not available — still show basic warnings
        }

        // Try contract risk check
        if (tx.to) {
          try {
            const riskResponse = await fetch(GUARDIAN_API + '/api/contract-risk/' + tx.to + '/ethereum');
            if (riskResponse.ok) {
              const riskData = await riskResponse.json();
              if (riskData.riskScore > 50) {
                riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
                riskData.findings.forEach(function(f) {
                  warnings.push(f.detail);
                });
              }
            }
          } catch (e) {
            // Backend not available
          }
        }
      }

      // For signing methods, always warn
      if (method === 'eth_sign') {
        riskLevel = 'CRITICAL';
        warnings.push('eth_sign is extremely dangerous. This can sign ANY data including transactions.');
      }

      if (method.includes('signTypedData')) {
        warnings.push('Signature request detected. Verify the data being signed before approving.');
        if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
      }

      // Show warning if any risks found
      if (warnings.length > 0) {
        // Send to content script for UI display
        window.postMessage({
          type: 'GUARDIAN_TX_INTERCEPT',
          riskLevel: riskLevel,
          method: method,
          warnings: warnings,
          timestamp: Date.now(),
        }, '*');

        // Wait for user decision
        const userDecision = await new Promise(function(resolve) {
          function handler(event) {
            if (event.data && event.data.type === 'GUARDIAN_TX_DECISION') {
              window.removeEventListener('message', handler);
              resolve(event.data.approved);
            }
          }
          window.addEventListener('message', handler);

          // Auto-reject after 30s timeout
          setTimeout(function() {
            window.removeEventListener('message', handler);
            resolve(false);
          }, 30000);
        });

        if (!userDecision) {
          throw new Error('Transaction rejected by Crypto Guardian');
        }
      }
    } catch (guardianError) {
      if (guardianError.message === 'Transaction rejected by Crypto Guardian') {
        throw guardianError;
      }
      // If Guardian itself errors, let the tx through (fail-open for usability)
      console.warn('[Crypto Guardian] Intercept error:', guardianError);
    }

    return originalRequest(args);
  };

  console.log('[Crypto Guardian] Transaction interceptor active');
})();
