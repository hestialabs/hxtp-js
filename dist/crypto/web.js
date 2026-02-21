// src/crypto/interface.ts
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
function bytesToHex(bytes) {
  const hex = [];
  for (let i = 0; i < bytes.length; i++) {
    hex.push((bytes[i] >>> 4).toString(16));
    hex.push((bytes[i] & 15).toString(16));
  }
  return hex.join("");
}
function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// src/crypto/web.ts
function getSubtle() {
  if (typeof globalThis.crypto?.subtle !== "undefined") {
    return globalThis.crypto.subtle;
  }
  throw new Error("Web Crypto API not available. Use hxtp-js/crypto/node for Node.js.");
}
function getCrypto() {
  if (typeof globalThis.crypto !== "undefined") {
    return globalThis.crypto;
  }
  throw new Error("crypto.getRandomValues not available in this environment.");
}
var encoder = new TextEncoder();
var WebCryptoProvider = class {
  async signHmacSha256(secret, data) {
    const subtle = getSubtle();
    const key = await subtle.importKey(
      "raw",
      secret.buffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await subtle.sign("HMAC", key, encoder.encode(data));
    return bytesToHex(new Uint8Array(sig));
  }
  async sha256Hex(data) {
    const subtle = getSubtle();
    const digest = await subtle.digest("SHA-256", encoder.encode(data));
    return bytesToHex(new Uint8Array(digest));
  }
  randomBytes(length) {
    const buf = new Uint8Array(length);
    getCrypto().getRandomValues(buf);
    return buf;
  }
};
var webCrypto = new WebCryptoProvider();
function generateNonce(byteLength = 16) {
  const bytes = new Uint8Array(byteLength);
  getCrypto().getRandomValues(bytes);
  return bytesToHex(bytes);
}

export { bytesToHex, constantTimeEqual, generateNonce, hexToBytes, webCrypto };
//# sourceMappingURL=web.js.map
//# sourceMappingURL=web.js.map