/**
 * @file types/index.ts
 * @description Re-exports all public types.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

export type {
    HXTPMessageHeader,
    HXTPEnvelope,
    ValidationResult,
    ProtocolErrorCode,
    MessageTypeValue,
    ChannelValue,
} from "./protocol.js";

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
} from "./protocol.js";

export type {
    HXTPConfig,
    HXTPEventType,
    HXTPMessageEvent,
    HXTPErrorEvent,
    HXTPEventHandler,
    HXTPCommandPayload,
    HXTPResponse,
} from "./client.js";
