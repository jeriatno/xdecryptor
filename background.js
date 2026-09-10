// Decryptor Background Service Worker
importScripts('dictionary.js', 'crypto-engine.js');

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "decryptSelection",
    title: "🔓 Decrypt / Inspect with Decryptor",
    contexts: ["selection"]
  });
});

// Helper for sending message to tab with dynamic script injection fallback
async function safelySendMessageToTab(tabId, message) {
  try {
    return await chrome.tabs.sendMessage(tabId, message);
  } catch (err) {
    if (err && err.message && err.message.includes("Could not establish connection")) {
      try {
        await chrome.scripting.insertCSS({
          target: { tabId },
          files: ["content.css"]
        });
        await chrome.scripting.executeScript({
          target: { tabId },
          files: ["content.js"]
        });
        return await chrome.tabs.sendMessage(tabId, message);
      } catch (injectionErr) {
        console.warn("CryptoDecrypt: Tab does not support content scripts (e.g. chrome:// URL).", injectionErr.message);
      }
    } else {
      console.warn("CryptoDecrypt: Message failed to send to tab:", err.message);
    }
  }
}

// Online reverse hash lookup fallback
async function queryOnlineHashDatabases(hash, hashType) {
  const cleanHash = hash.trim().toLowerCase();
  
  // 1. Try Nitrxgen (Fast MD5 database)
  if (hashType === 'MD5' || cleanHash.length === 32) {
    try {
      const resp = await fetch(`https://www.nitrxgen.net/md5db/${cleanHash}`, {
        method: 'GET',
        headers: { 'Accept': 'text/plain' }
      });
      if (resp.ok) {
        const text = (await resp.text()).trim();
        if (text && text.length > 0 && !text.includes('<html') && !text.includes('Error')) {
          return {
            success: true,
            plain: text,
            hashType: 'MD5',
            source: 'Nitrxgen Database',
            elapsedSeconds: '0.4'
          };
        }
      }
    } catch (e) {
      console.warn("Nitrxgen lookup failed:", e);
    }
  }

  // 2. Try Gromweb MD5 / SHA1
  if (cleanHash.length === 32 || cleanHash.length === 40) {
    try {
      const typeParam = cleanHash.length === 32 ? 'md5' : 'sha1';
      const resp = await fetch(`https://${typeParam}.gromweb.com/query/${cleanHash}`, {
        method: 'GET',
        headers: { 'Accept': 'text/plain' }
      });
      if (resp.ok) {
        const text = (await resp.text()).trim();
        if (text && text.length > 0 && !text.includes('<html') && !text.includes('not found')) {
          return {
            success: true,
            plain: text,
            hashType: typeParam.toUpperCase(),
            source: 'Gromweb Database',
            elapsedSeconds: '0.6'
          };
        }
      }
    } catch (e) {
      console.warn("Gromweb lookup failed:", e);
    }
  }

  return {
    success: false,
    hashType: hashType,
    message: "Hash not found in online reverse databases."
  };
}

// Context Menu Click Handler
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id || info.menuItemId !== "decryptSelection" || !info.selectionText) return;

  const rawText = info.selectionText.trim();
  if (!rawText) return;

  // Let the user know processing has started
  await safelySendMessageToTab(tab.id, {
    action: "showDecrypterLoading",
    rawText: rawText
  });

  const detections = CryptoEngine.detectFormat(rawText);
  let result = null;

  if (detections.length > 0 && detections[0].action === 'crack') {
    const topDetect = detections[0];
    // 1. Try local dictionary crack
    const localResult = await CryptoEngine.crackHash(rawText, CryptoDictionary);
    if (localResult.success) {
      result = localResult;
    } else {
      // 2. Fallback to online reverse API
      const onlineResult = await queryOnlineHashDatabases(rawText, topDetect.type);
      result = onlineResult.success ? onlineResult : localResult;
    }
  } else if (detections.length > 0 && detections[0].action === 'jwt') {
    try {
      const jwtData = CryptoEngine.jwtDecode(rawText);
      result = {
        success: true,
        type: 'JWT',
        payload: jwtData.payload,
        header: jwtData.header,
        expStatus: jwtData.expStatus,
        plain: JSON.stringify(jwtData.payload, null, 2)
      };
    } catch (e) {
      result = { success: false, error: e.message };
    }
  } else if (detections.length > 0 && detections[0].type === 'Base64') {
    try {
      const plain = CryptoEngine.base64Decode(rawText);
      result = { success: true, type: 'Base64', plain: plain };
    } catch (e) {
      result = { success: false, error: e.message };
    }
  } else if (detections.length > 0 && detections[0].type === 'Hex') {
    try {
      const plain = CryptoEngine.hexDecode(rawText);
      result = { success: true, type: 'Hex', plain: plain };
    } catch (e) {
      result = { success: false, error: e.message };
    }
  } else if (detections.length > 0 && detections[0].type === 'URL') {
    try {
      const plain = CryptoEngine.urlDecode(rawText);
      result = { success: true, type: 'URL', plain: plain };
    } catch (e) {
      result = { success: false, error: e.message };
    }
  } else if (detections.length > 0 && detections[0].type === 'Binary') {
    try {
      const plain = CryptoEngine.binaryDecode(rawText);
      result = { success: true, type: 'Binary', plain: plain };
    } catch (e) {
      result = { success: false, error: e.message };
    }
  } else {
    // General fallback: try Base64, ROT13, or reverse lookup
    try {
      const b64 = CryptoEngine.base64Decode(rawText);
      result = { success: true, type: 'Base64', plain: b64 };
    } catch (e) {
      result = {
        success: false,
        message: "Unable to automatically decrypt. Open CryptoDecrypt popup to inspect further."
      };
    }
  }

  // Send result to content script
  await safelySendMessageToTab(tab.id, {
    action: "showDecrypterResult",
    rawText: rawText,
    result: result,
    detections: detections
  });
});

// Runtime messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'queryOnlineHash') {
    queryOnlineHashDatabases(request.hash, request.hashType)
      .then(res => sendResponse(res))
      .catch(err => sendResponse({ success: false, message: err.message }));
    return true; // async sendResponse
  }
});
