<div align="center">
  <img src="icons/icon128.png" alt="Decryptor Logo" width="96" height="96" />
  <h1>Decryptor</h1>
  <p><strong>Chrome Extension (Manifest V3)</strong></p>
  <p>The universal cryptographic hash cracker and multi-cipher decoder for Google Chrome. Fast, offline-first, and lightweight.</p>
</div>

---

## 🚀 Key Features

### 1. ⚡ Smart Auto-Decrypt
- **Automatic Format Detection**: Instantly identifies whether an input string is **MD5**, **SHA-1**, **SHA-256**, **Base64**, **Hex**, **URL-encoded**, **JWT**, or **Binary**.
- **One-Click Execution**: Decrypts or decodes automatically with a single click—no need to manually select algorithms.
- **Quick Sample Buttons**: Built-in test chips for rapid verification.

### 2. 🔓 Dedicated Hash Cracker
- **Offline Rainbow Table & Wordlist**: Pre-loaded with over **10,000+** common passwords, PINs, dictionary words, and precomputed hash tables for instant matching (0.001s) with zero internet connection required.
- **Online Reverse Hash Lookup Fallback**: Background service worker automatically queries free global reverse lookup databases (Nitrxgen, Gromweb) if the hash is not in the local dictionary.
- **Supported Hash Types**: MD5 (128-bit), SHA-1 (160-bit), SHA-256 (256-bit), and SHA-512 (512-bit).

### 3. 🔄 Multi-Ciphers & Decoders
- **Base64 / Base64URL**: UTF-8 safe encode and decode (handles non-ASCII text, international characters, and emojis without corruption).
- **Hexadecimal (ASCII)**: Two-way conversion between Hex pairs and plain text.
- **URL / Percent-Encoding**: Deep decode support for multi-pass URL-encoded strings.
- **HTML Entities**: Decodes named and numeric entities (`&amp;`, `&quot;`, `&#x...;`, etc.).
- **Binary (8-bit)**: Converts 8-bit binary strings to text and vice versa.
- **Caesar / ROT13 Cipher**: Interactive shift slider (1 to 25) with live preview.
- **Atbash Cipher**: Classical A ⇄ Z alphabet reversal substitution.
- **Morse Code**: Bidirectional translation between Morse code and text.
- **⇄ Swap Button**: Instantly flips input and output for quick re-encoding/decoding.

### 4. 🎫 JWT (JSON Web Token) Inspector
- **Header & Payload Breakdown**: Formats tokens into syntax-highlighted, indented JSON objects.
- **Expiration Tracker**: Inspects expiration timestamps (`exp`) and displays real-time active or expired status with duration countdowns.

### 5. 🔐 AES Symmetric Crypto
- **AES-GCM (256-bit)**: Industry-standard symmetric encryption and decryption with PBKDF2 key derivation using a custom secret passphrase.

### 6. #️⃣ Hash Generator
- **Real-Time Hashing**: Generates MD5, SHA-1, SHA-256, and SHA-512 hashes simultaneously as you type, with individual one-click copy buttons.

### 7. 🌐 In-Page Floating Decryptor (Context Menu)
- Highlight any hash or encoded text on any webpage ➔ Right-click ➔ **"🔓 Decrypt / Inspect with Decryptor"**.
- An interactive floating card appears directly in the corner of the page with one-click copy functionality.

---

## 📁 File Structure

```text
decryptor/
├── .gitignore          # Git ignore rules
├── README.md           # Documentation
├── manifest.json       # Chrome Manifest V3 configuration
├── background.js       # Service worker for context menus & online reverse lookup
├── content.js          # In-page floating modal trigger & event handlers
├── content.css         # In-page floating modal styles
├── popup.html          # Clean Light Mode popup interface
├── popup.js            # Popup controller & UI logic
├── popup.css           # Modern Light Mode styles
├── crypto-engine.js    # Core cryptographic library (MD5, SHA, Base64, JWT, AES, etc.)
├── dictionary.js       # Offline rainbow table and 10,000+ entry wordlist
└── icons/
    ├── icon16.png      # 16x16 Favicon
    ├── icon48.png      # 48x48 Extension manager icon
    ├── icon128.png     # 128x128 Web store & main icon
    └── icon-decrypter.png # High-resolution source icon
```

---

## 💻 Installation Guide (Google Chrome)

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable the **Developer mode** toggle in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Select this directory (`decryptor`).
5. The extension is now active across all web pages.

---

## 📖 How to Use

### A. Quick Decryption via Popup
1. Click the **Decryptor** icon on your Chrome toolbar.
2. Under the **Smart Auto** tab, paste any hash or encoded string into the input box.
3. The format is auto-detected. Click **Decrypt Now** or press Enter.
4. Click **Copy Output** to copy the plain text to your clipboard.

### B. Hash Cracking
1. Open the popup and select the **Hash Cracker** tab.
2. Enter an MD5, SHA-1, or SHA-256 hash.
3. Ensure **Use Online DB fallback** is checked for comprehensive global lookup.
4. Click **Start Crack** to run the instant dictionary attack.

### C. In-Page Context Menu
1. Highlight any hash or encoded string on any website.
2. Right-click the highlighted text and select **"🔓 Decrypt / Inspect with Decryptor"**.
3. A floating card will appear in the top-right corner showing the decrypted result with a **Copy** button.
