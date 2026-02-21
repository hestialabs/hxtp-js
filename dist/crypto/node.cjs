'use strict';

var crypto = require('crypto');

// src/crypto/node.ts

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

// src/crypto/node.ts
var NodeCryptoProvider = class {
  async signHmacSha256(secret, data) {
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(data, "utf8");
    return hmac.digest("hex");
  }
  async sha256Hex(data) {
    const hash = crypto.createHash("sha256");
    hash.update(data, "utf8");
    return hash.digest("hex");
  }
  randomBytes(length) {
    return new Uint8Array(crypto.randomBytes(length));
  }
};
var nodeCrypto = new NodeCryptoProvider();
function nodeConstantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}
function generateNonce(byteLength = 16) {
  const bytes = crypto.randomBytes(byteLength);
  return bytesToHex(new Uint8Array(bytes));
}

exports.bytesToHex = bytesToHex;
exports.constantTimeEqual = constantTimeEqual;
exports.generateNonce = generateNonce;
exports.hexToBytes = hexToBytes;
exports.nodeConstantTimeEqual = nodeConstantTimeEqual;
exports.nodeCrypto = nodeCrypto;
//# sourceMappingURL=node.cjs.map
//# sourceMappingURL=node.cjs.map