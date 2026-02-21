'use strict';

var crypto = require('crypto');

var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

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
var init_interface = __esm({
  "src/crypto/interface.ts"() {
  }
});

// src/crypto/node.ts
var node_exports = {};
__export(node_exports, {
  bytesToHex: () => bytesToHex,
  constantTimeEqual: () => constantTimeEqual,
  generateNonce: () => generateNonce2,
  hexToBytes: () => hexToBytes,
  nodeConstantTimeEqual: () => nodeConstantTimeEqual,
  nodeCrypto: () => nodeCrypto
});
function nodeConstantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}
function generateNonce2(byteLength = 16) {
  const bytes = crypto.randomBytes(byteLength);
  return bytesToHex(new Uint8Array(bytes));
}
var NodeCryptoProvider, nodeCrypto;
var init_node = __esm({
  "src/crypto/node.ts"() {
    init_interface();
    init_interface();
    NodeCryptoProvider = class {
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
    nodeCrypto = new NodeCryptoProvider();
  }
});

// src/crypto/web.ts
var web_exports = {};
__export(web_exports, {
  bytesToHex: () => bytesToHex,
  constantTimeEqual: () => constantTimeEqual,
  generateNonce: () => generateNonce3,
  hexToBytes: () => hexToBytes,
  webCrypto: () => webCrypto
});
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
function generateNonce3(byteLength = 16) {
  const bytes = new Uint8Array(byteLength);
  getCrypto().getRandomValues(bytes);
  return bytesToHex(bytes);
}
var encoder, WebCryptoProvider, webCrypto;
var init_web = __esm({
  "src/crypto/web.ts"() {
    init_interface();
    init_interface();
    encoder = new TextEncoder();
    WebCryptoProvider = class {
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
    webCrypto = new WebCryptoProvider();
  }
});

// src/types/protocol.ts
var PROTOCOL_VERSION = "HxTP/2.2";
var CANONICAL_SEPARATOR = "|";
var MAX_MESSAGE_AGE_SEC = 300;
var TIMESTAMP_SKEW_SEC = 60;
var NONCE_TTL_SEC = 600;
var MAX_PAYLOAD_BYTES = 16384;
var HMAC_HEX_LENGTH = 64;
var SHA256_HEX_LENGTH = 64;
var MIN_NONCE_BYTES = 16;
var MessageType = {
  STATE: "state",
  COMMAND: "command",
  HEARTBEAT: "heartbeat",
  TELEMETRY: "telemetry",
  OTA: "ota",
  ACK: "ack",
  ERROR: "error"
};
var Channel = {
  STATE: "state",
  CMD: "cmd",
  CMD_ACK: "cmd_ack",
  HELLO: "hello",
  HEARTBEAT: "heartbeat",
  OTA: "ota",
  OTA_STATUS: "ota_status",
  TELEMETRY: "telemetry"
};
var ValidationStep = {
  VERSION: "VERSION_CHECK",
  TIMESTAMP: "TIMESTAMP_CHECK",
  PAYLOAD_SIZE: "PAYLOAD_SIZE_CHECK",
  NONCE: "NONCE_CHECK",
  PAYLOAD_HASH: "PAYLOAD_HASH_CHECK",
  SEQUENCE: "SEQUENCE_CHECK",
  SIGNATURE: "SIGNATURE_CHECK"
};
var ProtocolError = {
  VERSION_MISMATCH: "VERSION_MISMATCH",
  TIMESTAMP_EXPIRED: "TIMESTAMP_EXPIRED",
  TIMESTAMP_FUTURE: "TIMESTAMP_FUTURE",
  PAYLOAD_TOO_LARGE: "PAYLOAD_TOO_LARGE",
  NONCE_MISSING: "NONCE_MISSING",
  NONCE_REUSED: "NONCE_REUSED",
  HASH_MISMATCH: "HASH_MISMATCH",
  SEQUENCE_VIOLATION: "SEQUENCE_VIOLATION",
  SIGNATURE_MISSING: "SIGNATURE_MISSING",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  SECRET_MISSING: "SECRET_MISSING"
};

// src/core/signing.ts
init_interface();

// src/core/canonical.ts
function buildCanonical(msg) {
  const parts = [
    String(msg.version || msg.protocol_version || ""),
    String(msg.message_type || ""),
    String(msg.device_id || ""),
    String(msg.tenant_id || ""),
    String(msg.timestamp || ""),
    String(msg.message_id || ""),
    String(msg.nonce || "")
  ];
  return parts.join(CANONICAL_SEPARATOR);
}
function parseCanonical(canonical) {
  const parts = canonical.split(CANONICAL_SEPARATOR);
  return {
    version: parts[0] || "",
    message_type: parts[1] || "",
    device_id: parts[2] || "",
    tenant_id: parts[3] || "",
    timestamp: parts[4] || "",
    message_id: parts[5] || "",
    nonce: parts[6] || ""
  };
}
function validateCanonical(canonical) {
  const parts = canonical.split(CANONICAL_SEPARATOR);
  return parts.length === 7 && parts.every((p) => p.length > 0);
}

// src/core/signing.ts
async function signMessage(crypto, secretHex, msg) {
  if (!secretHex || secretHex.length !== 64) {
    throw new Error("Secret must be a 64-character hex string (32 bytes).");
  }
  const secretBytes = hexToBytes(secretHex);
  const canonical = buildCanonical(msg);
  return crypto.signHmacSha256(secretBytes, canonical);
}
async function verifySignature(crypto, secretHex, msg, signature) {
  if (!signature || signature.length !== HMAC_HEX_LENGTH) return false;
  if (!secretHex) return false;
  const computed = await signMessage(crypto, secretHex, msg);
  return constantTimeEqual(computed, signature);
}
async function verifySignatureWithFallback(crypto, activeSecretHex, previousSecretHex, msg, signature) {
  const activeValid = await verifySignature(crypto, activeSecretHex, msg, signature);
  if (activeValid) {
    return { valid: true, rotated: false };
  }
  if (previousSecretHex) {
    const prevValid = await verifySignature(crypto, previousSecretHex, msg, signature);
    if (prevValid) {
      return { valid: true, rotated: true };
    }
  }
  return { valid: false, rotated: false };
}

// src/core/nonce.ts
init_interface();
function generateNonce(crypto, byteLength = MIN_NONCE_BYTES) {
  if (byteLength < MIN_NONCE_BYTES) {
    throw new Error(`Nonce must be >= ${MIN_NONCE_BYTES} bytes.`);
  }
  return bytesToHex(crypto.randomBytes(byteLength));
}
var NonceCache = class {
  entries = [];
  maxSize;
  ttlMs;
  constructor(maxSize = 256, ttlSec = NONCE_TTL_SEC) {
    this.maxSize = maxSize;
    this.ttlMs = ttlSec * 1e3;
  }
  /**
   * Check if a nonce has been seen. Returns `true` if duplicate (replay).
   * Automatically records the nonce if new.
   */
  check(nonce) {
    const now = Date.now();
    this.evict(now);
    for (const entry of this.entries) {
      if (entry.nonce === nonce) return true;
    }
    this.entries.push({ nonce, timestampMs: now });
    if (this.entries.length > this.maxSize) {
      this.entries.shift();
    }
    return false;
  }
  /** Remove expired entries. */
  evict(now) {
    while (this.entries.length > 0 && now - this.entries[0].timestampMs > this.ttlMs) {
      this.entries.shift();
    }
  }
  /** Clear all entries. */
  clear() {
    this.entries.length = 0;
  }
  /** Current cache size. */
  get size() {
    return this.entries.length;
  }
};

// src/core/envelope.ts
init_interface();
async function buildEnvelope(opts) {
  const { crypto, secretHex, deviceId, tenantId, messageType, params } = opts;
  if (!secretHex || secretHex.length !== 64) {
    throw new Error("Secret must be a 64-character hex string (32 bytes).");
  }
  const messageId = generateUUID(crypto);
  const nonce = generateNonce(crypto);
  const timestamp = Date.now();
  const paramsJson = JSON.stringify(params ?? {});
  const payloadHash = await crypto.sha256Hex(paramsJson);
  const msgFields = {
    version: PROTOCOL_VERSION,
    message_type: messageType,
    device_id: deviceId,
    tenant_id: tenantId,
    timestamp,
    message_id: messageId,
    nonce
  };
  const signature = await signMessage(crypto, secretHex, msgFields);
  return {
    ...msgFields,
    client_id: opts.clientId,
    sequence_number: opts.sequence,
    payload_hash: payloadHash,
    signature,
    params
  };
}
function generateUUID(crypto) {
  const bytes = crypto.randomBytes(16);
  bytes[6] = bytes[6] & 15 | 64;
  bytes[8] = bytes[8] & 63 | 128;
  const hex = bytesToHex(bytes);
  return [
    hex.substring(0, 8),
    hex.substring(8, 12),
    hex.substring(12, 16),
    hex.substring(16, 20),
    hex.substring(20, 32)
  ].join("-");
}

// src/core/validation.ts
function pass() {
  return { ok: true, code: "", reason: "", rotated: false };
}
function fail(code, reason) {
  return { ok: false, code, reason, rotated: false };
}
async function validateMessage(msg, opts) {
  const maxAge = opts.maxMessageAgeSec ?? MAX_MESSAGE_AGE_SEC;
  const skew = opts.timestampSkewSec ?? TIMESTAMP_SKEW_SEC;
  const now = opts.nowMs ?? Date.now();
  const version = msg.version || msg.protocol_version || "";
  if (version !== PROTOCOL_VERSION) {
    return fail(ProtocolError.VERSION_MISMATCH, `Unsupported version: ${version}`);
  }
  const ts = typeof msg.timestamp === "number" ? msg.timestamp : 0;
  const nowSec = Math.floor(now / 1e3);
  let tsSec = ts;
  if (ts > 1e12) {
    tsSec = Math.floor(ts / 1e3);
  }
  const ageSec = nowSec - tsSec;
  if (ageSec > maxAge) {
    return fail(ProtocolError.TIMESTAMP_EXPIRED, `Message too old: ${ageSec}s`);
  }
  if (tsSec > nowSec + skew) {
    return fail(
      ProtocolError.TIMESTAMP_FUTURE,
      `Message from future: ${tsSec - nowSec}s ahead`
    );
  }
  if (msg.params) {
    const paramsStr = JSON.stringify(msg.params);
    if (paramsStr.length > MAX_PAYLOAD_BYTES) {
      return fail(
        ProtocolError.PAYLOAD_TOO_LARGE,
        `Payload exceeds ${MAX_PAYLOAD_BYTES} bytes`
      );
    }
  }
  if (!msg.nonce) {
    return fail(ProtocolError.NONCE_MISSING, "Missing nonce");
  }
  if (opts.nonceCache) {
    if (opts.nonceCache.check(msg.nonce)) {
      return fail(ProtocolError.NONCE_REUSED, "Nonce already seen (replay)");
    }
  }
  if (msg.payload_hash) {
    const paramsJson = JSON.stringify(msg.params ?? {});
    const computed = await opts.crypto.sha256Hex(paramsJson);
    if (computed !== msg.payload_hash) {
      return fail(ProtocolError.HASH_MISMATCH, "Payload hash mismatch");
    }
  }
  if (!msg.signature) {
    return fail(ProtocolError.SIGNATURE_MISSING, "Missing signature");
  }
  const sigResult = await verifySignatureWithFallback(
    opts.crypto,
    opts.activeSecret,
    opts.previousSecret,
    msg,
    msg.signature
  );
  if (!sigResult.valid) {
    return fail(ProtocolError.SIGNATURE_INVALID, "HMAC-SHA256 verification failed");
  }
  const result = pass();
  return { ...result, rotated: sigResult.rotated };
}

// src/crypto/detect.ts
async function detectCrypto() {
  if (typeof globalThis.process !== "undefined" && globalThis.process.versions?.node) {
    const mod = await Promise.resolve().then(() => (init_node(), node_exports));
    return mod.nodeCrypto;
  }
  if (typeof globalThis.Deno !== "undefined") {
    if (typeof globalThis.crypto?.subtle !== "undefined") {
      const mod = await Promise.resolve().then(() => (init_web(), web_exports));
      return mod.webCrypto;
    }
  }
  if (typeof globalThis.crypto?.subtle !== "undefined") {
    const mod = await Promise.resolve().then(() => (init_web(), web_exports));
    return mod.webCrypto;
  }
  throw new Error(
    "No supported crypto provider found. Provide a CryptoProvider via config.crypto, or use hxtp-js/crypto/node or hxtp-js/crypto/web."
  );
}
function detectReplayDefault() {
  if (typeof globalThis.process !== "undefined" && globalThis.process.versions?.node) {
    return true;
  }
  return false;
}

// src/transport/websocket.ts
var WebSocketTransport = class {
  socket = null;
  messageHandlers = [];
  closeHandlers = [];
  errorHandlers = [];
  _state = "disconnected";
  url;
  protocols;
  connectTimeoutMs;
  constructor(opts) {
    let url = opts.url;
    if (opts.token) {
      const sep = url.includes("?") ? "&" : "?";
      url = `${url}${sep}token=${encodeURIComponent(opts.token)}`;
    }
    this.url = url;
    this.protocols = opts.protocols;
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 1e4;
  }
  get state() {
    return this._state;
  }
  async connect() {
    if (this._state === "connected") return;
    this._state = "connecting";
    return new Promise((resolve, reject) => {
      const WS = resolveWebSocket();
      const socket = new WS(this.url, this.protocols);
      this.socket = socket;
      const timeout = setTimeout(() => {
        socket.close();
        this._state = "disconnected";
        reject(
          new Error(`WebSocket connection timed out after ${this.connectTimeoutMs}ms`)
        );
      }, this.connectTimeoutMs);
      socket.onopen = () => {
        clearTimeout(timeout);
        this._state = "connected";
        resolve();
      };
      socket.onmessage = (event) => {
        const data = typeof event.data === "string" ? event.data : String(event.data);
        for (const handler of this.messageHandlers) {
          handler(data);
        }
      };
      socket.onclose = (event) => {
        clearTimeout(timeout);
        this._state = "disconnected";
        this.socket = null;
        for (const handler of this.closeHandlers) {
          handler(event.code, event.reason);
        }
      };
      socket.onerror = () => {
        clearTimeout(timeout);
        const err = new Error("WebSocket connection error");
        for (const handler of this.errorHandlers) {
          handler(err);
        }
        if (this._state === "connecting") {
          this._state = "disconnected";
          reject(err);
        }
      };
    });
  }
  async disconnect() {
    if (!this.socket) return;
    this.socket.close(1e3, "Client disconnect");
    this.socket = null;
    this._state = "disconnected";
  }
  async send(data) {
    if (!this.socket || this._state !== "connected") {
      throw new Error("WebSocket not connected");
    }
    this.socket.send(data);
  }
  onMessage(handler) {
    this.messageHandlers.push(handler);
  }
  onClose(handler) {
    this.closeHandlers.push(handler);
  }
  onError(handler) {
    this.errorHandlers.push(handler);
  }
};
function resolveWebSocket() {
  if (typeof globalThis.WebSocket !== "undefined") {
    return globalThis.WebSocket;
  }
  throw new Error(
    "WebSocket not available. For Node.js 18-20, set globalThis.WebSocket to a WebSocket implementation (e.g., 'ws' package). Node.js 21+ has built-in WebSocket."
  );
}

// src/core/client.ts
var HXTPClient = class {
  config;
  transport = null;
  crypto = null;
  nonceCache = null;
  sequence = 0;
  heartbeatTimer = null;
  reconnectTimer = null;
  reconnectAttempt = 0;
  destroyed = false;
  listeners = /* @__PURE__ */ new Map();
  constructor(config) {
    if (!config.url) throw new Error("config.url is required");
    if (!config.tenantId) throw new Error("config.tenantId is required");
    if (!config.deviceId) throw new Error("config.deviceId is required");
    if (!config.secret) throw new Error("config.secret is required");
    if (config.secret.length !== 64) {
      throw new Error("config.secret must be a 64-character hex string");
    }
    this.config = config;
  }
  /** Connect to the server. Resolves when the connection is established. */
  async connect() {
    if (this.destroyed) throw new Error("Client has been destroyed");
    this.crypto = this.config.crypto ?? await detectCrypto();
    const replayEnabled = this.config.replayProtection ?? detectReplayDefault();
    if (replayEnabled) {
      this.nonceCache = new NonceCache();
    }
    this.transport = this.config.transport ?? new WebSocketTransport({ url: this.config.url });
    this.transport.onMessage((data) => this.handleMessage(data));
    this.transport.onClose((code, reason) => this.handleClose(code, reason));
    this.transport.onError((err) => this.handleError(err));
    await this.transport.connect();
    this.reconnectAttempt = 0;
    this.startHeartbeat();
    this.emit("connect", void 0);
  }
  /** Disconnect gracefully and release resources. */
  async disconnect() {
    this.destroyed = true;
    this.stopHeartbeat();
    this.stopReconnect();
    if (this.transport) {
      await this.transport.disconnect();
      this.transport = null;
    }
    this.nonceCache?.clear();
  }
  /**
   * Send a signed command to the server.
   *
   * Constructs a fully signed HxTP envelope with:
   *   - HMAC-SHA256 signature over frozen canonical string
   *   - SHA-256 payload hash
   *   - Cryptographic nonce
   *   - Monotonic sequence number
   */
  async sendCommand(payload) {
    if (!this.transport || this.transport.state !== "connected") {
      throw new Error("Not connected");
    }
    if (!this.crypto) {
      throw new Error("Crypto provider not initialized");
    }
    this.sequence++;
    const envelope = await buildEnvelope({
      crypto: this.crypto,
      secretHex: this.config.secret,
      deviceId: payload.deviceId ?? this.config.deviceId,
      tenantId: this.config.tenantId,
      clientId: this.config.clientId,
      messageType: MessageType.COMMAND,
      params: { action: payload.action, ...payload.params },
      sequence: this.sequence
    });
    const json = JSON.stringify(envelope);
    await this.transport.send(json);
    return {
      ok: true,
      messageId: envelope.message_id,
      timestamp: envelope.timestamp
    };
  }
  /** Register an event listener. */
  on(event, handler) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, /* @__PURE__ */ new Set());
    }
    this.listeners.get(event).add(handler);
  }
  /** Remove an event listener. */
  off(event, handler) {
    this.listeners.get(event)?.delete(handler);
  }
  /** Whether the client is currently connected. */
  get connected() {
    return this.transport?.state === "connected";
  }
  /** Current monotonic sequence number. */
  get currentSequence() {
    return this.sequence;
  }
  /* ── Private Methods ──────────────────────────────────────────────── */
  emit(event, data) {
    const handlers = this.listeners.get(event);
    if (!handlers) return;
    for (const handler of handlers) {
      try {
        handler(data);
      } catch {
      }
    }
  }
  async handleMessage(raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.emitError("PARSE_ERROR", "Invalid JSON message", false);
      return;
    }
    if (this.crypto && this.config.secret) {
      const result = await validateMessage(parsed, {
        crypto: this.crypto,
        activeSecret: this.config.secret,
        previousSecret: this.config.previousSecret,
        nonceCache: this.nonceCache ?? void 0,
        maxMessageAgeSec: this.config.maxMessageAgeSec,
        timestampSkewSec: this.config.timestampSkewSec
      });
      if (!result.ok) {
        this.emitError(result.code, result.reason, false);
        return;
      }
    }
    this.emit("message", {
      raw,
      parsed,
      timestamp: Date.now()
    });
  }
  handleClose(code, reason) {
    this.stopHeartbeat();
    this.emit("disconnect", { code, reason });
    if (!this.destroyed && (this.config.autoReconnect ?? true)) {
      this.scheduleReconnect();
    }
  }
  handleError(err) {
    this.emitError("TRANSPORT_ERROR", err.message, false);
  }
  emitError(code, message, fatal) {
    this.emit("error", { code, message, fatal });
  }
  startHeartbeat() {
    const interval = this.config.heartbeatIntervalMs ?? 3e4;
    this.heartbeatTimer = setInterval(() => {
      if (this.transport?.state === "connected" && this.crypto) {
        this.sendHeartbeat().catch(() => {
        });
      }
    }, interval);
  }
  /**
   * Send a signed heartbeat message.
   * No unsigned messages are allowed over an authenticated channel.
   * The heartbeat is a fully signed HxTP envelope with message_type: "heartbeat".
   */
  async sendHeartbeat() {
    if (!this.crypto || !this.transport || this.transport.state !== "connected") return;
    this.sequence++;
    const envelope = await buildEnvelope({
      crypto: this.crypto,
      secretHex: this.config.secret,
      deviceId: this.config.deviceId,
      tenantId: this.config.tenantId,
      clientId: this.config.clientId,
      messageType: MessageType.HEARTBEAT,
      params: {},
      sequence: this.sequence
    });
    await this.transport.send(JSON.stringify(envelope));
  }
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
  scheduleReconnect() {
    this.reconnectAttempt++;
    const base = this.config.reconnectDelayMs ?? 1e3;
    const max = this.config.maxReconnectDelayMs ?? 3e4;
    const delay = Math.min(base * Math.pow(2, this.reconnectAttempt - 1), max);
    this.emit("reconnecting", { attempt: this.reconnectAttempt, delayMs: delay });
    this.reconnectTimer = setTimeout(async () => {
      if (this.destroyed) return;
      try {
        await this.transport?.connect();
        this.reconnectAttempt = 0;
        this.startHeartbeat();
        this.emit("connect", void 0);
      } catch {
        this.scheduleReconnect();
      }
    }, delay);
  }
  stopReconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
};

// src/core/topics.ts
function buildTopic(tenantId, deviceId, channel) {
  return `hxtp/${tenantId}/device/${deviceId}/${channel}`;
}
function buildWildcard(channel) {
  return `hxtp/+/device/+/${channel}`;
}
function parseTopic(topic) {
  const parts = topic.split("/");
  if (parts.length !== 5 || parts[0] !== "hxtp" || parts[2] !== "device") {
    return null;
  }
  return {
    tenantId: parts[1],
    deviceId: parts[3],
    channel: parts[4]
  };
}

// src/index.ts
init_interface();

exports.CANONICAL_SEPARATOR = CANONICAL_SEPARATOR;
exports.Channel = Channel;
exports.HMAC_HEX_LENGTH = HMAC_HEX_LENGTH;
exports.HXTPClient = HXTPClient;
exports.MAX_MESSAGE_AGE_SEC = MAX_MESSAGE_AGE_SEC;
exports.MAX_PAYLOAD_BYTES = MAX_PAYLOAD_BYTES;
exports.MIN_NONCE_BYTES = MIN_NONCE_BYTES;
exports.MessageType = MessageType;
exports.NONCE_TTL_SEC = NONCE_TTL_SEC;
exports.NonceCache = NonceCache;
exports.PROTOCOL_VERSION = PROTOCOL_VERSION;
exports.ProtocolError = ProtocolError;
exports.SHA256_HEX_LENGTH = SHA256_HEX_LENGTH;
exports.TIMESTAMP_SKEW_SEC = TIMESTAMP_SKEW_SEC;
exports.ValidationStep = ValidationStep;
exports.buildCanonical = buildCanonical;
exports.buildEnvelope = buildEnvelope;
exports.buildTopic = buildTopic;
exports.buildWildcard = buildWildcard;
exports.bytesToHex = bytesToHex;
exports.constantTimeEqual = constantTimeEqual;
exports.detectCrypto = detectCrypto;
exports.generateNonce = generateNonce;
exports.hexToBytes = hexToBytes;
exports.parseCanonical = parseCanonical;
exports.parseTopic = parseTopic;
exports.signMessage = signMessage;
exports.validateCanonical = validateCanonical;
exports.validateMessage = validateMessage;
exports.verifySignature = verifySignature;
exports.verifySignatureWithFallback = verifySignatureWithFallback;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map