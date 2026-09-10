# Decryptor - Hash, Base64 & JWT Decoder
### Chrome Web Store Publishing Guide & SEO Metadata

## 📋 Store Listing Information

- **Extension Name**: Decryptor - Hash, Base64 & JWT Decoder
- **Short Description (< 132 chars)**: Instant decryptor & decoder for MD5, SHA hashes, Base64, Hex, URL encoding, JWT tokens, Caesar cipher, and AES.
- **Category**: Developer Tools
- **Target Keywords**: hash decoder, md5 decryptor, sha256 decoder, base64 decoder, jwt debugger, jwt decoder, hex decoder, url decoder, aes decryption, developer tools, cybersecurity

---

## 📝 Detailed Store Description

Quickly decode and decrypt hashes, encoded strings, and security tokens directly in your browser with one click!

Decryptor is an essential toolkit for cybersecurity professionals, web developers, penetration testers, and CTF enthusiasts. It automatically detects, decodes, and looks up encrypted or obfuscated text.

### 🌟 Supported Ciphers & Encodings:
- **🔑 Hash Reverse Lookups**: Look up MD5, SHA-1, SHA-256, and SHA-512 hashes using fast, reputable rainbow table APIs.
- **🔤 Base64 & Base32**: Decode standard and URL-safe Base64 strings with UTF-8 character support.
- **🌐 URL Encoding**: Quickly decode percent-encoded (%20) parameters and complex query strings.
- **🔢 Hexadecimal & Binary**: Convert hexadecimal bytes and binary streams back to readable ASCII/UTF-8.
- **🎫 JWT (JSON Web Token)**: Inspect and decode JWT Headers and Payloads with formatted JSON tree views and expiration date checks.
- **🏛️ Classic Ciphers**: Crack Caesar Cipher and ROT13 with automatic rotation brute-forcing.
- **🔒 AES Decryption**: Decrypt AES-CBC and AES-GCM payloads with a user-supplied key or passphrase.

### 🌟 User Experience:
- **Right-Click Context Menu**: Highlight any ciphertext on a webpage and click *Decrypt / Decode with Decryptor*.
- **In-Page Floating Modal**: Shows immediate decoding results without navigating away from your active tab.
- **Popup Utility**: Full-featured workbench to paste strings, auto-detect encoding type, and copy decoded output.

---

## 🔒 Permissions Justification

| Permission | Technical Need | Plain-English Justification for Reviewers |
| :--- | :--- | :--- |
| `contextMenus` | `chrome.contextMenus` API | Adds the right-click menu item "Decrypt / Decode" on selected text for fast analysis. |
| `activeTab` | `chrome.tabs` API | Grants temporary access to display the floating result modal on the active tab. |
| `scripting` | `chrome.scripting` API | Injects the decoding modal and copy buttons into the webpage DOM. |
| `storage` | `chrome.storage` API | Saves user preferences and recent decoding history locally. |
| `clipboardWrite` | `navigator.clipboard.writeText` | Allows users to copy decrypted plain text directly with a single click. |
| `https://www.nitrxgen.net/*` | Host Permission | Endpoint for reverse MD5/SHA hash rainbow table lookups. |
| `https://*.gromweb.com/*` | Host Permission | Secondary fallback API for reverse hash lookups. |
| `<all_urls>` | Host Permission & Content Script | Allows the extension to trigger selection decoding on any website. |

---

## 🛡️ Privacy & Data Use Disclosure

- **Zero Sensitive Data Logging**: Input strings are only processed locally for decoding (Base64, Hex, URL, JWT, Caesar, AES).
- **External Lookups**: Only anonymous MD5/SHA hash values are queried against public rainbow table APIs. No user credentials, cookies, or personal info are ever transmitted.
