/**
 * @file index.ts
 * @description hxtp-js — HxTP/2.2 JavaScript/TypeScript Client SDK.
 *
 * Public API surface. All exports are tree-shakeable.
 *
 * Usage:
 *   import { HXTPClient, buildCanonical, PROTOCOL_VERSION } from "hxtp-js";
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/* ── Client ──────────────────────────────────────────────────────────── */

export { HXTPClient } from "./core/client.js";

/* ── Core Functions ──────────────────────────────────────────────────── */

export { buildCanonical, parseCanonical, validateCanonical } from "./core/canonical.js";

export { signMessage, verifySignature, verifySignatureWithFallback } from "./core/signing.js";

export { buildEnvelope } from "./core/envelope.js";

export { validateMessage } from "./core/validation.js";

export { generateNonce, NonceCache } from "./core/nonce.js";

export { buildTopic, buildWildcard, parseTopic } from "./core/topics.js";

/* ── Crypto ──────────────────────────────────────────────────────────── */

export type { CryptoProvider } from "./crypto/interface.js";

export { constantTimeEqual, bytesToHex, hexToBytes } from "./crypto/interface.js";

export { detectCrypto } from "./crypto/detect.js";

/* ── Transport ───────────────────────────────────────────────────────── */

export type { Transport, TransportState } from "./transport/interface.js";

/* ── Types ───────────────────────────────────────────────────────────── */

export type {
    HXTPConfig,
    HXTPEventType,
    HXTPMessageEvent,
    HXTPErrorEvent,
    HXTPEventHandler,
    HXTPCommandPayload,
    HXTPResponse,
} from "./types/client.js";

export type {
    HXTPMessageHeader,
    HXTPEnvelope,
    ValidationResult,
    ProtocolErrorCode,
    MessageTypeValue,
    ChannelValue,
} from "./types/protocol.js";

export {
    PROTOCOL_VERSION,
    CANONICAL_SEPARATOR,
    MAX_MESSAGE_AGE_SEC,
    TIMESTAMP_SKEW_SEC,
    NONCE_TTL_SEC,
    MAX_PAYLOAD_BYTES,
    HMAC_HEX_LENGTH,
    SHA256_HEX_LENGTH,
    MIN_NONCE_BYTES,
    MessageType,
    Channel,
    ValidationStep,
    ProtocolError,
} from "./types/protocol.js";
