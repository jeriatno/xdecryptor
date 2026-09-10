// Decryptor - Popup Controller
document.addEventListener('DOMContentLoaded', () => {
  // Runtime messaging helper
  function safeSendMessage(msg, cb) {
    if (window.chrome && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage(msg, cb);
    } else {
      if (msg.action === 'queryOnlineHash') {
        const clean = (msg.hash || '').trim().toLowerCase();
        fetch(`https://www.nitrxgen.net/md5db/${clean}`)
          .then(r => r.text())
          .then(t => {
            const trimmed = (t || '').trim();
            if (trimmed && !trimmed.includes('<html') && !trimmed.includes('Error')) {
              cb({ success: true, plain: trimmed, hashType: msg.hashType || 'MD5', source: 'Nitrxgen DB', elapsedSeconds: '0.4' });
            } else {
              cb({ success: false });
            }
          })
          .catch(() => cb({ success: false }));
      }
    }
  }

  // Common UI Elements
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const statusBox = document.getElementById('statusBox');
  const statusMsg = document.getElementById('statusMsg');

  // ==========================================
  // 1. Tab Navigation
  // ==========================================
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const content = document.getElementById(targetTab);
      if (content) content.classList.add('active');
    });
  });

  // ==========================================
  // Status Bar Notification Helper
  // ==========================================
  let statusTimer = null;
  function setStatus(type, message) {
    if (statusTimer) clearTimeout(statusTimer);
    statusBox.className = `status-box status-${type}`;
    statusMsg.textContent = message;

    if (type !== 'loading' && type !== 'idle') {
      statusTimer = setTimeout(() => {
        statusBox.className = 'status-box status-idle';
        statusMsg.textContent = 'Ready.';
      }, 5000);
    }
  }

  // Clipboard Helper
  async function copyText(text, btnElement) {
    if (!text || text === '...') return;
    try {
      await navigator.clipboard.writeText(text);
      if (btnElement) {
        const orig = btnElement.innerHTML;
        btnElement.innerHTML = '<span>✓</span> Copied!';
        setTimeout(() => { btnElement.innerHTML = orig; }, 1800);
      }
      setStatus('success', 'Copied to clipboard!');
    } catch (e) {
      setStatus('error', 'Failed to copy to clipboard.');
    }
  }

  // ==========================================
  // 2. Tab 1: Smart Auto Decrypt
  // ==========================================
  const autoInput = document.getElementById('autoInput');
  const detectedBar = document.getElementById('detectedBar');
  const detectedPill = document.getElementById('detectedPill');
  const confidenceTag = document.getElementById('confidenceTag');
  const autoDecryptBtn = document.getElementById('autoDecryptBtn');
  const autoClearBtn = document.getElementById('autoClearBtn');
  const autoCopyBtn = document.getElementById('autoCopyBtn');
  const autoOutput = document.getElementById('autoOutput');
  const autoMetaInfo = document.getElementById('autoMetaInfo');

  function updateDetection() {
    const val = autoInput.value.trim();
    if (!val) {
      detectedBar.style.display = 'none';
      return;
    }
    const detections = CryptoEngine.detectFormat(val);
    if (detections.length > 0) {
      const top = detections[0];
      detectedBar.style.display = 'flex';
      detectedPill.textContent = `Detected: ${top.type}`;
      confidenceTag.textContent = `${top.description} (${top.confidence}%)`;
    } else {
      detectedBar.style.display = 'none';
    }
  }

  autoInput.addEventListener('input', updateDetection);

  async function performAutoDecrypt() {
    const text = autoInput.value.trim();
    if (!text) {
      setStatus('error', 'Please enter text to decrypt.');
      return;
    }

    setStatus('loading', 'Analyzing and decrypting...');
    autoOutput.textContent = 'Processing...';
    autoMetaInfo.textContent = '';

    const detections = CryptoEngine.detectFormat(text);
    const top = detections.length > 0 ? detections[0] : null;

    try {
      // Case 1: Hash Cracking (MD5, SHA-1, SHA-256)
      if (top && top.action === 'crack') {
        const localResult = await CryptoEngine.crackHash(text, CryptoDictionary);
        if (localResult.success) {
          autoOutput.textContent = localResult.plain;
          autoMetaInfo.textContent = `[${localResult.hashType}] Source: ${localResult.source} (${localResult.elapsedSeconds}s)`;
          setStatus('success', `Successfully cracked ${localResult.hashType}!`);
          return;
        }

        // Try Online Fallback
        setStatus('loading', 'Checking online reverse databases...');
        safeSendMessage({ action: 'queryOnlineHash', hash: text, hashType: top.type }, (onlineRes) => {
          if (onlineRes && onlineRes.success) {
            autoOutput.textContent = onlineRes.plain;
            autoMetaInfo.textContent = `[${onlineRes.hashType}] Source: ${onlineRes.source} (${onlineRes.elapsedSeconds}s)`;
            setStatus('success', `Cracked via ${onlineRes.source}!`);
          } else {
            autoOutput.textContent = `[Failed to crack hash]\n${localResult.message}\nOnline reverse databases also returned no match.`;
            autoMetaInfo.textContent = `[${top.type}] Not found`;
            setStatus('error', `Hash not found in dictionary or online databases.`);
          }
        });
        return;
      }

      // Case 2: JWT
      if (top && top.type === 'JWT') {
        const jwtData = CryptoEngine.jwtDecode(text);
        const formatted = JSON.stringify(jwtData.payload, null, 2);
        autoOutput.textContent = `// JWT Header:\n${JSON.stringify(jwtData.header, null, 2)}\n\n// JWT Payload (Claims):\n${formatted}\n\n// Status: ${jwtData.expHuman || jwtData.expStatus}`;
        autoMetaInfo.textContent = `[JWT] Alg: ${jwtData.algorithm} | ${jwtData.expStatus}`;
        setStatus('success', 'Decoded JWT Token!');
        return;
      }

      // Case 3: Base64
      if (top && top.type === 'Base64') {
        const decoded = CryptoEngine.base64Decode(text);
        autoOutput.textContent = decoded;
        autoMetaInfo.textContent = '[Base64] Decoded';
        setStatus('success', 'Decoded Base64 string!');
        return;
      }

      // Case 4: Hex
      if (top && top.type === 'Hex') {
        const decoded = CryptoEngine.hexDecode(text);
        autoOutput.textContent = decoded;
        autoMetaInfo.textContent = '[Hex] Decoded to ASCII';
        setStatus('success', 'Decoded Hex string!');
        return;
      }

      // Case 5: URL
      if (top && top.type === 'URL') {
        const decoded = CryptoEngine.urlDecode(text);
        autoOutput.textContent = decoded;
        autoMetaInfo.textContent = '[URL] Decoded';
        setStatus('success', 'Decoded URL encoded string!');
        return;
      }

      // Case 6: Binary
      if (top && top.type === 'Binary') {
        const decoded = CryptoEngine.binaryDecode(text);
        autoOutput.textContent = decoded;
        autoMetaInfo.textContent = '[Binary] Decoded';
        setStatus('success', 'Decoded 8-bit Binary string!');
        return;
      }

      // Fallback: Try Base64 or ROT13
      try {
        const b64 = CryptoEngine.base64Decode(text);
        autoOutput.textContent = b64;
        autoMetaInfo.textContent = '[Base64 Fallback]';
        setStatus('success', 'Decoded as Base64.');
        return;
      } catch (e) {}

      autoOutput.textContent = `[Could not auto-decrypt]\nTry selecting a specific algorithm from the 'Ciphers' tab or 'Hash Cracker'.`;
      autoMetaInfo.textContent = 'Unknown format';
      setStatus('error', 'Could not determine encryption or encoding format.');
    } catch (err) {
      autoOutput.textContent = `Error: ${err.message}`;
      setStatus('error', err.message);
    }
  }

  autoDecryptBtn.addEventListener('click', performAutoDecrypt);
  autoClearBtn.addEventListener('click', () => {
    autoInput.value = '';
    autoOutput.textContent = 'Hasil dekripsi akan muncul di sini...';
    autoMetaInfo.textContent = '';
    detectedBar.style.display = 'none';
    setStatus('idle', 'Cleared.');
  });
  autoCopyBtn.addEventListener('click', () => copyText(autoOutput.textContent, autoCopyBtn));

  // Sample buttons
  document.querySelectorAll('.chip-btn[data-sample]').forEach(btn => {
    btn.addEventListener('click', () => {
      const sample = btn.getAttribute('data-sample');
      const targetId = btn.getAttribute('data-target') || 'autoInput';
      const targetElem = document.getElementById(targetId);
      if (targetElem) {
        targetElem.value = sample;
        if (targetId === 'autoInput') {
          updateDetection();
          performAutoDecrypt();
        }
      }
    });
  });

  // ==========================================
  // 3. Tab 2: Dedicated Hash Cracker
  // ==========================================
  const hashInput = document.getElementById('hashInput');
  const checkOnlineFallback = document.getElementById('checkOnlineFallback');
  const crackBtn = document.getElementById('crackBtn');
  const clearHashBtn = document.getElementById('clearHashBtn');
  const copyCrackedBtn = document.getElementById('copyCrackedBtn');
  const crackOutput = document.getElementById('crackOutput');
  const crackMetaInfo = document.getElementById('crackMetaInfo');
  const crackProgressBar = document.getElementById('crackProgressBar');
  const progressFill = document.getElementById('progressFill');
  const progressPercent = document.getElementById('progressPercent');
  const progressText = document.getElementById('progressText');

  crackBtn.addEventListener('click', async () => {
    const hash = hashInput.value.trim();
    if (!hash) {
      setStatus('error', 'Please enter a target hash.');
      return;
    }

    crackOutput.textContent = 'Cracking in progress...';
    crackMetaInfo.textContent = '';
    crackProgressBar.style.display = 'flex';
    progressFill.style.width = '0%';
    progressPercent.textContent = '0%';
    progressText.textContent = 'Checking local dictionary...';
    setStatus('loading', 'Cracking cryptographic hash...');

    try {
      const result = await CryptoEngine.crackHash(hash, CryptoDictionary, (p) => {
        progressFill.style.width = `${p.percent}%`;
        progressPercent.textContent = `${p.percent}%`;
        progressText.textContent = `Testing word ${p.current} of ${p.total}...`;
      });

      if (result.success) {
        crackProgressBar.style.display = 'none';
        crackOutput.textContent = result.plain;
        crackMetaInfo.textContent = `[${result.hashType}] ${result.source} (${result.elapsedSeconds}s)`;
        setStatus('success', `Hash cracked in ${result.elapsedSeconds}s!`);
        return;
      }

      // If not found and online fallback enabled
      if (checkOnlineFallback.checked) {
        progressText.textContent = 'Querying online reverse hash databases...';
        progressFill.style.width = '75%';
        progressPercent.textContent = '...';

        safeSendMessage({ action: 'queryOnlineHash', hash: hash, hashType: result.hashType }, (onlineRes) => {
          crackProgressBar.style.display = 'none';
          if (onlineRes && onlineRes.success) {
            crackOutput.textContent = onlineRes.plain;
            crackMetaInfo.textContent = `[${onlineRes.hashType}] ${onlineRes.source} (${onlineRes.elapsedSeconds}s)`;
            setStatus('success', `Cracked via online database!`);
          } else {
            crackOutput.textContent = `[Hash Not Found]\nChecked ${CryptoDictionary.wordlist.length} local entries and online reverse databases. No plaintext found.`;
            crackMetaInfo.textContent = 'Cracking Failed';
            setStatus('error', 'No match found for this hash.');
          }
        });
      } else {
        crackProgressBar.style.display = 'none';
        crackOutput.textContent = `[Hash Not Found]\nChecked ${CryptoDictionary.wordlist.length} entries in local dictionary. Enable online fallback to check global reverse DBs.`;
        crackMetaInfo.textContent = 'Local miss';
        setStatus('error', 'Hash not found in local dictionary.');
      }
    } catch (err) {
      crackProgressBar.style.display = 'none';
      crackOutput.textContent = `Error: ${err.message}`;
      setStatus('error', err.message);
    }
  });

  clearHashBtn.addEventListener('click', () => {
    hashInput.value = '';
    crackOutput.textContent = 'Waiting for hash...';
    crackMetaInfo.textContent = '';
    crackProgressBar.style.display = 'none';
    setStatus('idle', 'Cleared.');
  });
  copyCrackedBtn.addEventListener('click', () => copyText(crackOutput.textContent, copyCrackedBtn));

  // ==========================================
  // 4. Tab 3: Multi-Ciphers
  // ==========================================
  const cipherType = document.getElementById('cipherType');
  const modeDecode = document.getElementById('modeDecode');
  const modeEncode = document.getElementById('modeEncode');
  const caesarOptionRow = document.getElementById('caesarOptionRow');
  const caesarShift = document.getElementById('caesarShift');
  const shiftValue = document.getElementById('shiftValue');
  const cipherInput = document.getElementById('cipherInput');
  const cipherOutput = document.getElementById('cipherOutput');
  const cipherProcessBtn = document.getElementById('cipherProcessBtn');
  const cipherActionText = document.getElementById('cipherActionText');
  const cipherSwapBtn = document.getElementById('cipherSwapBtn');
  const cipherClearBtn = document.getElementById('cipherClearBtn');
  const cipherCopyBtn = document.getElementById('cipherCopyBtn');

  let cipherMode = 'decode'; // 'decode' or 'encode'

  modeDecode.addEventListener('click', () => {
    cipherMode = 'decode';
    modeDecode.classList.add('active');
    modeEncode.classList.remove('active');
    cipherActionText.textContent = 'Decode';
    processCipher();
  });

  modeEncode.addEventListener('click', () => {
    cipherMode = 'encode';
    modeEncode.classList.add('active');
    modeDecode.classList.remove('active');
    cipherActionText.textContent = 'Encode';
    processCipher();
  });

  cipherType.addEventListener('change', () => {
    if (cipherType.value === 'caesar') {
      caesarOptionRow.style.display = 'flex';
    } else {
      caesarOptionRow.style.display = 'none';
    }
    processCipher();
  });

  caesarShift.addEventListener('input', () => {
    const s = parseInt(caesarShift.value, 10);
    shiftValue.textContent = s === 13 ? '13 (ROT13)' : s;
    processCipher();
  });

  function processCipher() {
    const input = cipherInput.value;
    if (!input) {
      cipherOutput.textContent = '...';
      return;
    }

    const type = cipherType.value;
    const isEncode = cipherMode === 'encode';

    try {
      let result = '';
      switch (type) {
        case 'base64':
          result = isEncode ? CryptoEngine.base64Encode(input) : CryptoEngine.base64Decode(input);
          break;
        case 'hex':
          result = isEncode ? CryptoEngine.hexEncode(input) : CryptoEngine.hexDecode(input);
          break;
        case 'url':
          result = isEncode ? CryptoEngine.urlEncode(input) : CryptoEngine.urlDecode(input);
          break;
        case 'html':
          result = isEncode ? CryptoEngine.htmlEncode(input) : CryptoEngine.htmlDecode(input);
          break;
        case 'binary':
          result = isEncode ? CryptoEngine.binaryEncode(input) : CryptoEngine.binaryDecode(input);
          break;
        case 'caesar':
          const shift = parseInt(caesarShift.value, 10);
          result = isEncode ? CryptoEngine.caesar(input, shift) : CryptoEngine.caesar(input, 26 - shift);
          break;
        case 'atbash':
          result = CryptoEngine.atbash(input);
          break;
        case 'morse':
          result = isEncode ? CryptoEngine.morseEncode(input) : CryptoEngine.morseDecode(input);
          break;
        default:
          result = input;
      }
      cipherOutput.textContent = result;
      setStatus('success', `${isEncode ? 'Encoded' : 'Decoded'} via ${type.toUpperCase()}`);
    } catch (e) {
      cipherOutput.textContent = `Error: ${e.message}`;
      setStatus('error', e.message);
    }
  }

  cipherProcessBtn.addEventListener('click', processCipher);
  cipherInput.addEventListener('input', processCipher);

  cipherSwapBtn.addEventListener('click', () => {
    const curOut = cipherOutput.textContent;
    if (curOut && curOut !== '...' && !curOut.startsWith('Error:')) {
      cipherInput.value = curOut;
      if (cipherMode === 'decode') {
        modeEncode.click();
      } else {
        modeDecode.click();
      }
    }
  });

  cipherClearBtn.addEventListener('click', () => {
    cipherInput.value = '';
    cipherOutput.textContent = '...';
    setStatus('idle', 'Cleared.');
  });
  cipherCopyBtn.addEventListener('click', () => copyText(cipherOutput.textContent, cipherCopyBtn));

  // ==========================================
  // 5. Tab 4: JWT Inspector
  // ==========================================
  const jwtInput = document.getElementById('jwtInput');
  const sampleJwtBtn = document.getElementById('sampleJwtBtn');
  const jwtDecodeBtn = document.getElementById('jwtDecodeBtn');
  const jwtClearBtn = document.getElementById('jwtClearBtn');
  const jwtCopyPayloadBtn = document.getElementById('jwtCopyPayloadBtn');
  const jwtResultsArea = document.getElementById('jwtResultsArea');
  const jwtHeaderDisplay = document.getElementById('jwtHeaderDisplay');
  const jwtPayloadDisplay = document.getElementById('jwtPayloadDisplay');
  const jwtStatusBadge = document.getElementById('jwtStatusBadge');
  const jwtTimeInfo = document.getElementById('jwtTimeInfo');
  const jwtAlgBadge = document.getElementById('jwtAlgBadge');

  sampleJwtBtn.addEventListener('click', () => {
    const h = CryptoEngine.base64Encode(JSON.stringify({ alg: "HS256", typ: "JWT" }), true);
    const exp = Math.floor(Date.now() / 1000) + 7200;
    const p = CryptoEngine.base64Encode(JSON.stringify({
      sub: "1234567890",
      name: "Jeri Admin",
      role: "superadmin",
      iat: Math.floor(Date.now() / 1000),
      exp: exp
    }), true);
    const sampleToken = `${h}.${p}.sample_signature_hash_example`;
    jwtInput.value = sampleToken;
    parseJwt();
  });

  function parseJwt() {
    const token = jwtInput.value.trim();
    if (!token) {
      jwtResultsArea.style.display = 'none';
      setStatus('error', 'Please enter a JWT token.');
      return;
    }

    try {
      const data = CryptoEngine.jwtDecode(token);
      jwtHeaderDisplay.textContent = JSON.stringify(data.header, null, 2);
      jwtPayloadDisplay.textContent = JSON.stringify(data.payload, null, 2);

      jwtAlgBadge.textContent = data.algorithm;
      jwtTimeInfo.textContent = data.expHuman;

      if (data.expStatus === 'Active') {
        jwtStatusBadge.className = 'jwt-pill active';
        jwtStatusBadge.textContent = 'Active (Valid)';
      } else if (data.expStatus === 'Expired') {
        jwtStatusBadge.className = 'jwt-pill expired';
        jwtStatusBadge.textContent = 'Expired';
      } else {
        jwtStatusBadge.className = 'jwt-pill';
        jwtStatusBadge.textContent = 'No Expiration';
      }

      jwtResultsArea.style.display = 'block';
      setStatus('success', 'JWT Parsed successfully.');
    } catch (e) {
      jwtResultsArea.style.display = 'none';
      setStatus('error', e.message);
    }
  }

  jwtDecodeBtn.addEventListener('click', parseJwt);
  jwtClearBtn.addEventListener('click', () => {
    jwtInput.value = '';
    jwtResultsArea.style.display = 'none';
    setStatus('idle', 'Cleared.');
  });
  jwtCopyPayloadBtn.addEventListener('click', () => copyText(jwtPayloadDisplay.textContent, jwtCopyPayloadBtn));

  // ==========================================
  // 6. Tab 5: AES Symmetric Crypto
  // ==========================================
  const aesKey = document.getElementById('aesKey');
  const aesInput = document.getElementById('aesInput');
  const aesOutput = document.getElementById('aesOutput');
  const aesModeDecrypt = document.getElementById('aesModeDecrypt');
  const aesModeEncrypt = document.getElementById('aesModeEncrypt');
  const aesProcessBtn = document.getElementById('aesProcessBtn');
  const aesActionIcon = document.getElementById('aesActionIcon');
  const aesActionText = document.getElementById('aesActionText');
  const aesClearBtn = document.getElementById('aesClearBtn');
  const aesCopyBtn = document.getElementById('aesCopyBtn');

  let aesMode = 'decrypt'; // 'decrypt' or 'encrypt'

  aesModeDecrypt.addEventListener('click', () => {
    aesMode = 'decrypt';
    aesModeDecrypt.classList.add('active');
    aesModeEncrypt.classList.remove('active');
    aesActionIcon.textContent = '🔓';
    aesActionText.textContent = 'Decrypt';
    aesInput.placeholder = 'Paste Base64 AES ciphertext...';
  });

  aesModeEncrypt.addEventListener('click', () => {
    aesMode = 'encrypt';
    aesModeEncrypt.classList.add('active');
    aesModeDecrypt.classList.remove('active');
    aesActionIcon.textContent = '🔒';
    aesActionText.textContent = 'Encrypt';
    aesInput.placeholder = 'Enter plain text to encrypt...';
  });

  aesProcessBtn.addEventListener('click', async () => {
    const key = aesKey.value;
    const input = aesInput.value.trim();

    if (!key) {
      setStatus('error', 'Please enter a secret key or passphrase.');
      return;
    }
    if (!input) {
      setStatus('error', 'Please enter ciphertext or plaintext.');
      return;
    }

    setStatus('loading', 'Processing AES (GCM-256)...');
    try {
      if (aesMode === 'encrypt') {
        const encryptedB64 = await CryptoEngine.aesEncrypt(input, key);
        aesOutput.textContent = encryptedB64;
        setStatus('success', 'AES Encrypted successfully!');
      } else {
        const decrypted = await CryptoEngine.aesDecrypt(input, key);
        aesOutput.textContent = decrypted;
        setStatus('success', 'AES Decrypted successfully!');
      }
    } catch (err) {
      aesOutput.textContent = `Error: ${err.message}`;
      setStatus('error', err.message);
    }
  });

  aesClearBtn.addEventListener('click', () => {
    aesInput.value = '';
    aesOutput.textContent = 'Waiting for input...';
    setStatus('idle', 'Cleared.');
  });
  aesCopyBtn.addEventListener('click', () => copyText(aesOutput.textContent, aesCopyBtn));

  // ==========================================
  // 7. Tab 6: Hash Generator
  // ==========================================
  const genInput = document.getElementById('genInput');
  const genMd5 = document.getElementById('genMd5');
  const genSha1 = document.getElementById('genSha1');
  const genSha256 = document.getElementById('genSha256');
  const genSha512 = document.getElementById('genSha512');

  async function updateHashes() {
    const text = genInput.value;
    if (!text) {
      genMd5.textContent = '-';
      genSha1.textContent = '-';
      genSha256.textContent = '-';
      genSha512.textContent = '-';
      return;
    }

    genMd5.textContent = CryptoEngine.md5(text);
    genSha1.textContent = await CryptoEngine.sha1(text);
    genSha256.textContent = await CryptoEngine.sha256(text);
    genSha512.textContent = await CryptoEngine.sha512(text);
  }

  genInput.addEventListener('input', updateHashes);

  document.querySelectorAll('.copy-small-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const copyId = btn.getAttribute('data-copy-id');
      const elem = document.getElementById(copyId);
      if (elem) copyText(elem.textContent, btn);
    });
  });
});
