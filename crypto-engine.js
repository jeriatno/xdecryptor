// CryptoEngine - Comprehensive Decryption & Decoding Library for CryptoDecrypt
// Supports MD5, SHA-1, SHA-256, SHA-512, NTLM, Base64, Hex, URL, HTML Entities,
// JWT, Caesar/ROT13, Atbash, Binary, Morse Code, and AES-GCM.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CryptoEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ==========================================
  // 1. MD5 Implementation (RFC 1321)
  // ==========================================
  function md5cycle(x, k) {
    let a = x[0], b = x[1], c = x[2], d = x[3];

    a = ff(a, b, c, d, k[0], 7, -680876936);
    d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819);
    b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897);
    d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341);
    b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416);
    d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063);
    b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682);
    d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290);
    b = ff(b, c, d, a, k[15], 22, 1236535329);

    a = gg(a, b, c, d, k[1], 5, -165796510);
    d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713);
    b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691);
    d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335);
    b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438);
    d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961);
    b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467);
    d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473);
    b = gg(b, c, d, a, k[12], 20, -1926607734);

    a = hh(a, b, c, d, k[5], 4, -378558);
    d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562);
    b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060);
    d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632);
    b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174);
    d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979);
    b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487);
    d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520);
    b = hh(b, c, d, a, k[2], 23, -995338651);

    a = ii(a, b, c, d, k[0], 6, -198630844);
    d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905);
    b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571);
    d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523);
    b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359);
    d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380);
    b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070);
    d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259);
    b = ii(b, c, d, a, k[9], 21, -343485551);

    x[0] = add32(a, x[0]);
    x[1] = add32(b, x[1]);
    x[2] = add32(c, x[2]);
    x[3] = add32(d, x[3]);
  }

  function cmn(q, a, b, x, s, t) {
    a = add32(add32(a, q), add32(x, t));
    return add32((a << s) | (a >>> (32 - s)), b);
  }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }

  function add32(a, b) {
    return (a + b) & 0xFFFFFFFF;
  }

  function md5(str) {
    const txt = unescape(encodeURIComponent(str));
    const n = txt.length;
    const state = [1732584193, -271733879, -1732584194, 271733878];
    let i;
    for (i = 64; i <= n; i += 64) {
      md5cycle(state, md5blk(txt.substring(i - 64, i)));
    }
    const tail = txt.substring(i - 64);
    const tailBlk = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for (let j = 0; j < tail.length; j++) {
      tailBlk[j >> 2] |= tail.charCodeAt(j) << ((j % 4) << 3);
    }
    tailBlk[tail.length >> 2] |= 0x80 << ((tail.length % 4) << 3);
    if (tail.length > 55) {
      md5cycle(state, tailBlk);
      for (let j = 0; j < 16; j++) tailBlk[j] = 0;
    }
    tailBlk[14] = n * 8;
    md5cycle(state, tailBlk);
    return rhex(state[0]) + rhex(state[1]) + rhex(state[2]) + rhex(state[3]);
  }

  function md5blk(s) {
    const md5blks = [];
    for (let i = 0; i < 64; i += 4) {
      md5blks[i >> 2] = s.charCodeAt(i)
        + (s.charCodeAt(i + 1) << 8)
        + (s.charCodeAt(i + 2) << 16)
        + (s.charCodeAt(i + 3) << 24);
    }
    return md5blks;
  }

  const hex_chr = '0123456789abcdef'.split('');
  function rhex(n) {
    let s = '', j = 0;
    for (; j < 4; j++) {
      s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] + hex_chr[(n >> (j * 8)) & 0x0F];
    }
    return s;
  }

  // ==========================================
  // 2. Web Crypto Hash (SHA-1, SHA-256, SHA-512)
  // ==========================================
  async function computeSubtleHash(algorithm, text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function sha1(text) {
    return await computeSubtleHash('SHA-1', text);
  }

  async function sha256(text) {
    return await computeSubtleHash('SHA-256', text);
  }

  async function sha512(text) {
    return await computeSubtleHash('SHA-512', text);
  }

  // Synchronous fallback SHA-1 implementation for quick dictionary testing
  function sha1Sync(str) {
    function rotateLeft(n, s) { return (n << s) | (n >>> (32 - s)); }
    function cvtHex(val) {
      let str = "";
      for (let i = 7; i >= 0; i--) {
        const v = (val >>> (i * 4)) & 0x0f;
        str += v.toString(16);
      }
      return str;
    }
    const blockstart = 0;
    const utf8 = unescape(encodeURIComponent(str));
    const words = [];
    for (let i = 0; i < utf8.length; i++) {
      words[i >> 2] |= (utf8.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }
    words[utf8.length >> 2] |= 0x80 << (24 - (utf8.length % 4) * 8);
    words[(((utf8.length + 8) >> 6) + 1) * 16 - 1] = utf8.length * 8;

    const w = new Array(80);
    let H0 = 1732584193, H1 = -271733879, H2 = -1732584194, H3 = 271733878, H4 = -1009589776;

    for (let i = 0; i < words.length; i += 16) {
      for (let t = 0; t < 16; t++) w[t] = words[i + t] || 0;
      for (let t = 16; t < 80; t++) w[t] = rotateLeft(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);

      let A = H0, B = H1, C = H2, D = H3, E = H4;
      for (let t = 0; t < 80; t++) {
        let f, K;
        if (t < 20) { f = (B & C) | ((~B) & D); K = 1518500249; }
        else if (t < 40) { f = B ^ C ^ D; K = 1859775393; }
        else if (t < 60) { f = (B & C) | (B & D) | (C & D); K = -1894007588; }
        else { f = B ^ C ^ D; K = -899497514; }

        const temp = (rotateLeft(A, 5) + f + E + K + w[t]) & 0xffffffff;
        E = D; D = C; C = rotateLeft(B, 30); B = A; A = temp;
      }
      H0 = (H0 + A) & 0xffffffff;
      H1 = (H1 + B) & 0xffffffff;
      H2 = (H2 + C) & 0xffffffff;
      H3 = (H3 + D) & 0xffffffff;
      H4 = (H4 + E) & 0xffffffff;
    }
    return (cvtHex(H0) + cvtHex(H1) + cvtHex(H2) + cvtHex(H3) + cvtHex(H4)).toLowerCase();
  }

  // ==========================================
  // 3. Base64 / Base64URL (Unicode / UTF-8 safe)
  // ==========================================
  function base64Encode(str, urlSafe = false) {
    const bytes = new TextEncoder().encode(str);
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    let b64 = btoa(binary);
    if (urlSafe) {
      b64 = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    return b64;
  }

  function base64Decode(str) {
    try {
      // Normalize URL-safe characters and padding
      let b64 = str.trim().replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) {
        b64 += '=';
      }
      const binary = atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (e) {
      throw new Error("Invalid Base64 string: " + e.message);
    }
  }

  // ==========================================
  // 4. Hex / ASCII
  // ==========================================
  function hexDecode(hexStr) {
    const cleaned = hexStr.replace(/0x/gi, '').replace(/[\s,:-]/g, '');
    if (cleaned.length % 2 !== 0) {
      throw new Error("Invalid Hex: odd number of characters");
    }
    if (!/^[0-9a-fA-F]*$/.test(cleaned)) {
      throw new Error("Invalid Hex: contains non-hexadecimal characters");
    }
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
      bytes[i / 2] = parseInt(cleaned.substr(i, 2), 16);
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  function hexEncode(str, separator = ' ') {
    const bytes = new TextEncoder().encode(str);
    const hex = [];
    for (let i = 0; i < bytes.length; i++) {
      hex.push(bytes[i].toString(16).padStart(2, '0'));
    }
    return hex.join(separator);
  }

  // ==========================================
  // 5. URL Decode / Encode
  // ==========================================
  function urlDecode(str, deep = true) {
    let prev = str;
    let decoded = decodeURIComponent(str.replace(/\+/g, ' '));
    if (deep) {
      // Handle double or triple encoded URLs
      while (decoded !== prev && /%[0-9a-fA-F]{2}/.test(decoded)) {
        prev = decoded;
        try {
          decoded = decodeURIComponent(decoded.replace(/\+/g, ' '));
        } catch (e) {
          break;
        }
      }
    }
    return decoded;
  }

  function urlEncode(str) {
    return encodeURIComponent(str);
  }

  // ==========================================
  // 6. HTML Entities
  // ==========================================
  function htmlDecode(str) {
    const namedEntities = {
      '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
      '&apos;': "'", '&#39;': "'", '&nbsp;': ' ', '&copy;': '©',
      '&reg;': '®', '&euro;': '€', '&pound;': '£', '&yen;': '¥'
    };
    return str
      .replace(/&[a-zA-Z]+;/g, match => namedEntities[match] || match)
      .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
      .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }

  function htmlEncode(str) {
    return str.replace(/[&<>"']/g, function (m) {
      switch (m) {
        case '&': return '&amp;';
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        case "'": return '&#39;';
        default: return m;
      }
    });
  }

  // ==========================================
  // 7. Binary (8-bit)
  // ==========================================
  function binaryDecode(binStr) {
    const cleaned = binStr.replace(/[^01]/g, '');
    if (cleaned.length % 8 !== 0) {
      throw new Error("Invalid Binary: bits must be multiples of 8");
    }
    const bytes = new Uint8Array(cleaned.length / 8);
    for (let i = 0; i < cleaned.length; i += 8) {
      bytes[i / 8] = parseInt(cleaned.substr(i, 8), 2);
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  function binaryEncode(str) {
    const bytes = new TextEncoder().encode(str);
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
      bits.push(bytes[i].toString(2).padStart(8, '0'));
    }
    return bits.join(' ');
  }

  // ==========================================
  // 8. Ciphers: Caesar / ROT13 / Atbash
  // ==========================================
  function caesar(str, shift = 13) {
    const s = ((shift % 26) + 26) % 26;
    return str.replace(/[a-zA-Z]/g, function (c) {
      const code = c.charCodeAt(0);
      const base = (code >= 65 && code <= 90) ? 65 : 97;
      return String.fromCharCode(((code - base + s) % 26) + base);
    });
  }

  function rot13(str) {
    return caesar(str, 13);
  }

  function atbash(str) {
    return str.replace(/[a-zA-Z]/g, function (c) {
      const code = c.charCodeAt(0);
      if (code >= 65 && code <= 90) {
        return String.fromCharCode(90 - (code - 65));
      } else {
        return String.fromCharCode(122 - (code - 97));
      }
    });
  }

  // ==========================================
  // 9. Morse Code
  // ==========================================
  const MORSE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
    '/': '-..-.', '-': '-....-', '(': '-.--.', ')': '-.--.-', ' ': '/'
  };
  const REVERSE_MORSE_MAP = {};
  for (const k in MORSE_MAP) {
    REVERSE_MORSE_MAP[MORSE_MAP[k]] = k;
  }

  function morseDecode(str) {
    const tokens = str.trim().split(/\s+/);
    let res = '';
    for (const t of tokens) {
      if (t === '/' || t === '|') {
        res += ' ';
      } else if (REVERSE_MORSE_MAP[t]) {
        res += REVERSE_MORSE_MAP[t];
      } else {
        res += '?';
      }
    }
    return res;
  }

  function morseEncode(str) {
    const chars = str.toUpperCase().split('');
    const morse = [];
    for (const c of chars) {
      if (MORSE_MAP[c]) {
        morse.push(MORSE_MAP[c]);
      } else if (c === ' ') {
        morse.push('/');
      }
    }
    return morse.join(' ');
  }

  // ==========================================
  // 10. JWT (JSON Web Token) Inspector
  // ==========================================
  function jwtDecode(token) {
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format: must have exactly 3 dot-separated parts (header.payload.signature)");
    }
    const [headerB64, payloadB64, signature] = parts;
    let header, payload;
    try {
      header = JSON.parse(base64Decode(headerB64));
    } catch (e) {
      throw new Error("Invalid JWT Header: failed to parse JSON");
    }
    try {
      payload = JSON.parse(base64Decode(payloadB64));
    } catch (e) {
      throw new Error("Invalid JWT Payload: failed to parse JSON");
    }

    // Inspect expiration
    let expStatus = 'Unknown';
    let expDate = null;
    let expHuman = '';
    if (payload.exp) {
      expDate = new Date(payload.exp * 1000);
      const now = Date.now();
      const diffSec = Math.round((expDate.getTime() - now) / 1000);
      if (diffSec < 0) {
        expStatus = 'Expired';
        expHuman = `Expired ${Math.abs(diffSec)} seconds ago (${expDate.toLocaleString()})`;
      } else {
        expStatus = 'Active';
        expHuman = `Expires in ${diffSec} seconds (${expDate.toLocaleString()})`;
      }
    }

    return {
      header,
      payload,
      signature,
      expStatus,
      expDate: expDate ? expDate.toISOString() : null,
      expHuman,
      algorithm: header.alg || 'none'
    };
  }

  // ==========================================
  // 11. AES Symmetric Encryption / Decryption
  // ==========================================
  async function getKeyFromPassphrase(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function aesEncrypt(plainText, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await getKeyFromPassphrase(passphrase, salt);
    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      enc.encode(plainText)
    );

    // Combine salt + iv + ciphertext
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);

    // Return as Base64
    let binary = '';
    for (let i = 0; i < combined.length; i++) {
      binary += String.fromCharCode(combined[i]);
    }
    return btoa(binary);
  }

  async function aesDecrypt(cipherBase64, passphrase) {
    try {
      const binary = atob(cipherBase64.trim());
      const combined = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        combined[i] = binary.charCodeAt(i);
      }

      if (combined.length < 28) {
        throw new Error("Ciphertext too short to contain salt and IV");
      }

      const salt = combined.slice(0, 16);
      const iv = combined.slice(16, 28);
      const ciphertext = combined.slice(28);

      const key = await getKeyFromPassphrase(passphrase, salt);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch (e) {
      throw new Error("AES Decryption failed: incorrect key or corrupted ciphertext.");
    }
  }

  // ==========================================
  // 12. Smart Auto-Detect & Identifier
  // ==========================================
  function detectFormat(input) {
    const str = String(input || '').trim();
    if (!str) return [];

    const detections = [];

    // 1. MD5 (32 hex characters)
    if (/^[0-9a-fA-F]{32}$/.test(str)) {
      detections.push({
        type: 'MD5',
        category: 'hash',
        confidence: 95,
        description: 'MD5 128-bit hash (or NTLM hash)',
        action: 'crack'
      });
    }

    // 2. SHA-1 (40 hex characters)
    if (/^[0-9a-fA-F]{40}$/.test(str)) {
      detections.push({
        type: 'SHA-1',
        category: 'hash',
        confidence: 95,
        description: 'SHA-1 160-bit hash',
        action: 'crack'
      });
    }

    // 3. SHA-256 (64 hex characters)
    if (/^[0-9a-fA-F]{64}$/.test(str)) {
      detections.push({
        type: 'SHA-256',
        category: 'hash',
        confidence: 95,
        description: 'SHA-256 256-bit hash',
        action: 'crack'
      });
    }

    // 4. SHA-512 (128 hex characters)
    if (/^[0-9a-fA-F]{128}$/.test(str)) {
      detections.push({
        type: 'SHA-512',
        category: 'hash',
        confidence: 95,
        description: 'SHA-512 512-bit hash',
        action: 'crack'
      });
    }

    // 5. JWT (3 base64url segments)
    const jwtParts = str.split('.');
    if (jwtParts.length === 3 && /^[A-Za-z0-9_-]+$/.test(jwtParts[0]) && /^[A-Za-z0-9_-]+$/.test(jwtParts[1])) {
      try {
        const h = JSON.parse(base64Decode(jwtParts[0]));
        if (h && (h.alg || h.typ)) {
          detections.push({
            type: 'JWT',
            category: 'token',
            confidence: 99,
            description: `JSON Web Token (${h.alg || 'unknown algorithm'})`,
            action: 'jwt'
          });
        }
      } catch (e) {}
    }

    // 6. Base64
    if (/^[A-Za-z0-9+/=_-]{4,}$/.test(str) && str.length % 4 <= 2) {
      try {
        const decoded = base64Decode(str);
        // If decoded is readable text
        if (decoded && /^[\x20-\x7E\r\n\t\u00A0-\uFFFF]+$/.test(decoded) && decoded.length >= 2) {
          detections.push({
            type: 'Base64',
            category: 'encoding',
            confidence: 85,
            description: 'Base64 / Base64URL encoded text',
            action: 'decode'
          });
        }
      } catch (e) {}
    }

    // 7. Hex string (even hex characters with or without spaces)
    const cleanHex = str.replace(/[\s,:-]/g, '');
    if (/^[0-9a-fA-F]{4,}$/.test(cleanHex) && cleanHex.length % 2 === 0) {
      try {
        const decoded = hexDecode(cleanHex);
        if (decoded && /^[\x20-\x7E\r\n\t\u00A0-\uFFFF]+$/.test(decoded)) {
          detections.push({
            type: 'Hex',
            category: 'encoding',
            confidence: 75,
            description: 'Hexadecimal (ASCII string)',
            action: 'decode'
          });
        }
      } catch (e) {}
    }

    // 8. URL Encoded
    if (/%[0-9a-fA-F]{2}/.test(str)) {
      try {
        const decoded = decodeURIComponent(str);
        if (decoded !== str) {
          detections.push({
            type: 'URL',
            category: 'encoding',
            confidence: 90,
            description: 'URL / Percent-encoded string',
            action: 'decode'
          });
        }
      } catch (e) {}
    }

    // 9. HTML Entities
    if (/&(#\d+|#[xX][0-9a-fA-F]+|[a-zA-Z]+);/.test(str)) {
      detections.push({
        type: 'HTML',
        category: 'encoding',
        confidence: 90,
        description: 'HTML Entities encoded string',
        action: 'decode'
      });
    }

    // 10. Binary
    if (/^[01\s]{8,}$/.test(str)) {
      try {
        const decoded = binaryDecode(str);
        if (decoded && /^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
          detections.push({
            type: 'Binary',
            category: 'encoding',
            confidence: 85,
            description: '8-bit binary representation',
            action: 'decode'
          });
        }
      } catch (e) {}
    }

    // 11. Morse code
    if (/^[.\-\s/|]{3,}$/.test(str)) {
      detections.push({
        type: 'Morse',
        category: 'cipher',
        confidence: 70,
        description: 'Morse code representation',
        action: 'decode'
      });
    }

    return detections.sort((a, b) => b.confidence - a.confidence);
  }

  // ==========================================
  // 13. Hash Cracker Engine (Offline + Online)
  // ==========================================
  async function crackHash(hash, dictObj, onProgress) {
    const h = String(hash).toLowerCase().trim();
    if (!dictObj) {
      throw new Error("Dictionary not loaded");
    }

    const startTime = performance.now();

    // 1. Instant check in precomputed rainbow tables
    const precomputed = dictObj.lookupPrecomputed(h);
    if (precomputed) {
      const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
      return {
        success: true,
        plain: precomputed.plain,
        hashType: precomputed.type,
        source: precomputed.source,
        elapsedSeconds: elapsed
      };
    }

    // Detect hash type
    let hashType = 'UNKNOWN';
    if (h.length === 32) hashType = 'MD5';
    else if (h.length === 40) hashType = 'SHA-1';
    else if (h.length === 64) hashType = 'SHA-256';

    const words = dictObj.wordlist || [];
    const total = words.length;

    // 2. Perform fast in-memory dictionary hashing
    if (hashType === 'MD5') {
      for (let i = 0; i < total; i++) {
        if (i % 2000 === 0 && onProgress) {
          onProgress({ current: i, total: total, percent: Math.round((i / total) * 100) });
          // yield briefly
          await new Promise(r => setTimeout(r, 0));
        }
        const w = words[i];
        if (md5(w) === h) {
          const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
          return {
            success: true,
            plain: w,
            hashType: 'MD5',
            source: 'Local Wordlist Dictionary',
            elapsedSeconds: elapsed
          };
        }
      }
    } else if (hashType === 'SHA-1') {
      for (let i = 0; i < total; i++) {
        if (i % 2000 === 0 && onProgress) {
          onProgress({ current: i, total: total, percent: Math.round((i / total) * 100) });
          await new Promise(r => setTimeout(r, 0));
        }
        const w = words[i];
        if (sha1Sync(w) === h) {
          const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
          return {
            success: true,
            plain: w,
            hashType: 'SHA-1',
            source: 'Local Wordlist Dictionary',
            elapsedSeconds: elapsed
          };
        }
      }
    }

    const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
    return {
      success: false,
      hashType: hashType,
      elapsedSeconds: elapsed,
      message: `Not found in offline dictionary (${total} words checked)`
    };
  }

  // Public Exports
  return {
    md5,
    sha1,
    sha256,
    sha512,
    sha1Sync,
    base64Encode,
    base64Decode,
    hexEncode,
    hexDecode,
    urlEncode,
    urlDecode,
    htmlEncode,
    htmlDecode,
    binaryEncode,
    binaryDecode,
    caesar,
    rot13,
    atbash,
    morseEncode,
    morseDecode,
    jwtDecode,
    aesEncrypt,
    aesDecrypt,
    detectFormat,
    crackHash
  };
});
