// Decryptor Content Script
// Displays interactive in-page floating results when triggered via context menu or hotkey.

(function () {
  let currentModal = null;
  let autoDismissTimer = null;

  function removeExistingModal() {
    if (autoDismissTimer) {
      clearTimeout(autoDismissTimer);
      autoDismissTimer = null;
    }
    if (currentModal && currentModal.parentNode) {
      currentModal.parentNode.removeChild(currentModal);
      currentModal = null;
    }
  }

  function showLoading(rawText) {
    removeExistingModal();

    const overlay = document.createElement('div');
    overlay.className = 'cd-modal-overlay';
    overlay.id = 'cd-floating-decrypter';

    overlay.innerHTML = `
      <div class="cd-card">
        <div class="cd-header">
          <div class="cd-title-wrap">
            <span class="cd-logo">🔓</span>
            <span class="cd-title">Decryptor</span>
            <span class="cd-badge">Processing...</span>
          </div>
          <button class="cd-close-btn" title="Close">×</button>
        </div>
        <div class="cd-body">
          <div class="cd-label">Target Text</div>
          <div class="cd-input-preview">${escapeHtml(rawText.substring(0, 100))}${rawText.length > 100 ? '...' : ''}</div>
          <div style="display: flex; align-items: center; gap: 8px; padding: 12px 0; color: #94a3b8; font-size: 12px;">
            <div class="cd-loading-spinner"></div>
            <span>Analyzing & Decrypting / Cracking...</span>
          </div>
        </div>
      </div>
    `;

    overlay.querySelector('.cd-close-btn').addEventListener('click', removeExistingModal);
    document.body.appendChild(overlay);
    currentModal = overlay;
  }

  function showResult(rawText, result, detections) {
    removeExistingModal();

    const overlay = document.createElement('div');
    overlay.className = 'cd-modal-overlay';
    overlay.id = 'cd-floating-decrypter';

    const topDetect = detections && detections.length > 0 ? detections[0] : null;
    const typeLabel = topDetect ? topDetect.type : (result && result.hashType ? result.hashType : 'Unknown');
    const isSuccess = result && result.success;

    const sourceLabel = result && result.source ? `Source: ${result.source}` : '';
    const elapsedLabel = result && result.elapsedSeconds ? `(${result.elapsedSeconds}s)` : '';

    let resultHtml = '';
    if (isSuccess) {
      resultHtml = `
        <div class="cd-result-box">
          <div class="cd-label" style="color: #38bdf8;">Decrypted Plaintext:</div>
          <div class="cd-result-text" id="cd-decrypted-output">${escapeHtml(result.plain || '')}</div>
        </div>
        <div class="cd-footer-bar">
          <span class="cd-source-info">${sourceLabel} ${elapsedLabel}</span>
          <button class="cd-copy-btn" id="cd-btn-copy">
            <span>📋</span> Copy
          </button>
        </div>
      `;
    } else {
      const errMsg = result && (result.message || result.error) ? (result.message || result.error) : 'Unable to crack or decrypt this string.';
      resultHtml = `
        <div class="cd-result-box" style="border-color: #ef4444; background: rgba(239, 68, 68, 0.08);">
          <div class="cd-label" style="color: #f87171;">Decryption Failed</div>
          <div style="color: #fca5a5; font-size: 12px; line-height: 1.4;">${escapeHtml(errMsg)}</div>
        </div>
        <div class="cd-footer-bar">
          <span class="cd-source-info">Try opening extension popup for advanced tools</span>
        </div>
      `;
    }

    overlay.innerHTML = `
      <div class="cd-card">
        <div class="cd-header">
          <div class="cd-title-wrap">
            <span class="cd-logo">🔓</span>
            <span class="cd-title">Decryptor</span>
            <span class="cd-badge ${isSuccess ? 'cd-badge-success' : 'cd-badge-danger'}">${escapeHtml(typeLabel)}</span>
          </div>
          <button class="cd-close-btn" title="Close">×</button>
        </div>
        <div class="cd-body">
          <div class="cd-label">Target Text</div>
          <div class="cd-input-preview">${escapeHtml(rawText.substring(0, 100))}${rawText.length > 100 ? '...' : ''}</div>
          ${resultHtml}
        </div>
      </div>
    `;

    overlay.querySelector('.cd-close-btn').addEventListener('click', removeExistingModal);

    const copyBtn = overlay.querySelector('#cd-btn-copy');
    if (copyBtn && isSuccess) {
      copyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(result.plain || '');
          copyBtn.innerHTML = '<span>✓</span> Copied!';
          setTimeout(() => {
            if (copyBtn) copyBtn.innerHTML = '<span>📋</span> Copy';
          }, 2000);
        } catch (e) {
          console.warn("Clipboard write failed:", e);
        }
      });
    }

    document.body.appendChild(overlay);
    currentModal = overlay;

    // Auto-dismiss after 15 seconds
    autoDismissTimer = setTimeout(() => {
      removeExistingModal();
    }, 15000);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Runtime message listener from background worker
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'showDecrypterLoading') {
      showLoading(request.rawText);
      sendResponse({ received: true });
    } else if (request.action === 'showDecrypterResult') {
      showResult(request.rawText, request.result, request.detections);
      sendResponse({ received: true });
    }
  });
})();
