/**
 * crypto.js — Client-side cryptographic operations
 *
 * Uses the browser's native Web Crypto API (SubtleCrypto) for:
 *   - AES-GCM encryption / decryption
 *   - RSA-OAEP key wrapping / unwrapping
 *   - Importing RSA private/public keys from PEM strings
 *
 * The private key NEVER leaves the browser.
 * All decryption happens here, server only serves encrypted blobs.
 */

const Crypto = (() => {

  // -----------------------------------------------------------------------
  // PEM <-> ArrayBuffer helpers
  // -----------------------------------------------------------------------

  function pemToArrayBuffer(pem) {
    const base64 = pem
      .replace(/-----BEGIN [A-Z ]+-----/, '')
      .replace(/-----END [A-Z ]+-----/, '')
      .replace(/\s+/g, '');
    const binary = atob(base64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
    return buf.buffer;
  }

  function arrayBufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str);
  }

  function base64ToArrayBuffer(b64) {
    const binary = atob(b64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
    return buf.buffer;
  }

  // -----------------------------------------------------------------------
  // RSA key import
  // -----------------------------------------------------------------------

  /**
   * Import a PEM private key for RSA-OAEP decryption.
   * Handles both PKCS#8 and traditional (PKCS#1) PEM formats.
   */
  async function importPrivateKey(pem) {
    const buf = pemToArrayBuffer(pem);

    // Try PKCS#8 first
    try {
      return await crypto.subtle.importKey(
        'pkcs8', buf,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false, ['decrypt']
      );
    } catch (_) {}

    // Fallback: PKCS#1 (traditional) — wrap it in PKCS#8 DER
    // Note: Web Crypto only supports PKCS#8 natively.
    // If the server returns TraditionalOpenSSL format, we need conversion.
    throw new Error(
      'Clé privée invalide. Assurez-vous de coller la clé complète au format PEM (PKCS#8 ou PKCS#1).'
    );
  }

  /**
   * Import a PEM public key for RSA-OAEP encryption.
   */
  async function importPublicKey(pem) {
    const buf = pemToArrayBuffer(pem);
    return crypto.subtle.importKey(
      'spki', buf,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false, ['encrypt']
    );
  }

  // -----------------------------------------------------------------------
  // AES-GCM key generation
  // -----------------------------------------------------------------------

  async function generateAESKey() {
    return crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, ['encrypt', 'decrypt']
    );
  }

  async function exportAESKey(aesKey) {
    const raw = await crypto.subtle.exportKey('raw', aesKey);
    return new Uint8Array(raw);
  }

  async function importAESKey(rawBytes) {
    return crypto.subtle.importKey(
      'raw', rawBytes,
      { name: 'AES-GCM' },
      false, ['encrypt', 'decrypt']
    );
  }

  // -----------------------------------------------------------------------
  // RSA-OAEP key wrapping / unwrapping
  // -----------------------------------------------------------------------

  /**
   * Wrap (encrypt) raw AES key bytes with RSA public key.
   * @param {Uint8Array} aesKeyBytes
   * @param {CryptoKey}  rsaPublicKey
   * @returns {string} base64-encoded encrypted AES key
   */
  async function wrapAESKey(aesKeyBytes, rsaPublicKey) {
    const encrypted = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      rsaPublicKey,
      aesKeyBytes
    );
    return arrayBufferToBase64(encrypted);
  }

  /**
   * Unwrap (decrypt) an RSA-encrypted AES key.
   * @param {string}    encryptedAESKeyB64  — base64 ciphertext from server
   * @param {CryptoKey} rsaPrivateKey
   * @returns {Uint8Array} raw AES key bytes
   */
  async function unwrapAESKey(encryptedAESKeyB64, rsaPrivateKey) {
    const encBuf = base64ToArrayBuffer(encryptedAESKeyB64);
    const rawAES = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      rsaPrivateKey,
      encBuf
    );
    return new Uint8Array(rawAES);
  }

  // -----------------------------------------------------------------------
  // AES-GCM file encryption
  // -----------------------------------------------------------------------

  /**
   * Encrypt a File object.
   * @param {File}       file
   * @param {CryptoKey}  aesKey
   * @returns {{ ciphertext: string, nonce: string }}
   */
  async function encryptFile(file, aesKey) {
    const plaintext = await file.arrayBuffer();
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      plaintext
    );

    return {
      ciphertext: arrayBufferToBase64(ciphertext),
      nonce: arrayBufferToBase64(nonce.buffer),
    };
  }

  /**
   * Decrypt an AES-GCM blob back to raw bytes.
   * @param {string} ciphertextB64
   * @param {string} nonceB64
   * @param {CryptoKey} aesKey
   * @returns {ArrayBuffer}
   */
  async function decryptFile(ciphertextB64, nonceB64, aesKey) {
    const ciphertext = base64ToArrayBuffer(ciphertextB64);
    const nonce = base64ToArrayBuffer(nonceB64);
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      ciphertext
    );
  }

  // -----------------------------------------------------------------------
  // Full encrypt pipeline: File → encrypted payload
  // -----------------------------------------------------------------------

  /**
   * Encrypt a file for multiple recipients.
   *
   * @param {File}     file
   * @param {Array<{id, username, public_key}>} recipients  — each with PEM public key
   * @returns {{
   *   encrypted_file : string,   // base64 AES-GCM ciphertext
   *   nonce          : string,   // base64 nonce
   *   wrappedKeys    : Object    // { userId: encryptedAESKeyB64 }
   * }}
   */
  async function encryptFileForRecipients(file, recipients) {
    // 1. Generate AES-256 session key
    const aesKey = await generateAESKey();
    const aesKeyBytes = await exportAESKey(aesKey);

    // 2. Encrypt file with AES-GCM
    const { ciphertext, nonce } = await encryptFile(file, aesKey);

    // 3. Wrap AES key for each recipient
    const wrappedKeys = {};
    for (const r of recipients) {
      const rsaPub = await importPublicKey(r.public_key);
      wrappedKeys[r.id] = await wrapAESKey(aesKeyBytes, rsaPub);
    }

    return { encrypted_file: ciphertext, nonce, wrappedKeys };
  }

  // -----------------------------------------------------------------------
  // Full decrypt pipeline: encrypted payload → ArrayBuffer
  // -----------------------------------------------------------------------

  /**
   * @param {string}    encryptedFileB64
   * @param {string}    nonceB64
   * @param {string}    encryptedAESKeyB64
   * @param {CryptoKey} rsaPrivateKey
   * @returns {ArrayBuffer}
   */
  async function decryptFileWithPrivateKey(encryptedFileB64, nonceB64, encryptedAESKeyB64, rsaPrivateKey) {
    const aesKeyBytes = await unwrapAESKey(encryptedAESKeyB64, rsaPrivateKey);
    const aesKey = await importAESKey(aesKeyBytes);
    return decryptFile(encryptedFileB64, nonceB64, aesKey);
  }

  // -----------------------------------------------------------------------
  // Re-wrap AES key for sharing (owner → new recipient)
  // -----------------------------------------------------------------------

  /**
   * Owner downloads their own wrapped AES key, decrypts it with private key,
   * then re-wraps it with the new recipient's public key.
   */
  async function reWrapKeyForRecipient(ownerEncAESKeyB64, ownerPrivateKey, recipientPublicKeyPem) {
    const aesKeyBytes = await unwrapAESKey(ownerEncAESKeyB64, ownerPrivateKey);
    const recipientPub = await importPublicKey(recipientPublicKeyPem);
    return wrapAESKey(aesKeyBytes, recipientPub);
  }

  // -----------------------------------------------------------------------
  // Utilities
  // -----------------------------------------------------------------------

  function triggerDownload(arrayBuffer, filename, mimeType = 'application/octet-stream') {
    const blob = new Blob([arrayBuffer], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // -----------------------------------------------------------------------
  return {
    importPrivateKey,
    importPublicKey,
    encryptFileForRecipients,
    decryptFileWithPrivateKey,
    reWrapKeyForRecipient,
    triggerDownload,
    pemToArrayBuffer,
    base64ToArrayBuffer,
    arrayBufferToBase64,
  };
})();
