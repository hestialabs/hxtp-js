/**
 * @file types/protocol.ts
 * @description HxTP/2.2 protocol type definitions.
 * All types are frozen and aligned with embedded SDK v1.0 + backend.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/* ── Protocol Constants (FROZEN) ─────────────────────────────────────── */

export const PROTOCOL_VERSION = "HxTP/2.2" as const;
export const CANONICAL_SEPARATOR = "|" as const;
export const MAX_MESSAGE_AGE_SEC = 300;
export const TIMESTAMP_SKEW_SEC = 60;
export const NONCE_TTL_SEC = 600;
export const MAX_PAYLOAD_BYTES = 16_384;
export const HMAC_HEX_LENGTH = 64;
export const SHA256_HEX_LENGTH = 64;
export const MIN_NONCE_BYTES = 16;

/* ── Message Types ───────────────────────────────────────────────────── */

export const MessageType = {
    STATE: "state",
    COMMAND: "command",
    HEARTBEAT: "heartbeat",
    TELEMETRY: "telemetry",
    OTA: "ota",
    ACK: "ack",
    ERROR: "error",
} as const;

export type MessageTypeValue = (typeof MessageType)[keyof typeof MessageType];

/* ── MQTT Topic Channels ─────────────────────────────────────────────── */

export const Channel = {
    STATE: "state",
    CMD: "cmd",
    CMD_ACK: "cmd_ack",
    HELLO: "hello",
    HEARTBEAT: "heartbeat",
    OTA: "ota",
    OTA_STATUS: "ota_status",
    TELEMETRY: "telemetry",
} as const;

export type ChannelValue = (typeof Channel)[keyof typeof Channel];

/* ── Message Header ──────────────────────────────────────────────────── */

export interface HXTPMessageHeader {
    readonly version: string;
    readonly message_type: MessageTypeValue;
    readonly message_id: string;
    readonly device_id: string;
    readonly tenant_id: string;
    readonly client_id?: string;
    readonly timestamp: number;
    readonly sequence_number?: number;
    readonly nonce: string;
    readonly payload_hash: string;
    readonly signature: string;
}

/* ── Outbound Envelope (pre-signature) ───────────────────────────────── */

export interface HXTPEnvelope {
    readonly version: string;
    readonly message_type: MessageTypeValue;
    readonly message_id: string;
    readonly device_id: string;
    readonly tenant_id: string;
    readonly client_id?: string;
    readonly timestamp: number;
    readonly sequence_number?: number;
    readonly nonce: string;
    readonly payload_hash: string;
    readonly signature: string;
    readonly params?: Record<string, unknown>;
    readonly [key: string]: unknown;
}

/* ── Validation Result ───────────────────────────────────────────────── */

export interface ValidationResult {
    readonly ok: boolean;
    readonly code: string;
    readonly reason: string;
    readonly rotated: boolean;
}

/* ── Validation Step Enum ────────────────────────────────────────────── */

export const ValidationStep = {
    VERSION: "VERSION_CHECK",
    TIMESTAMP: "TIMESTAMP_CHECK",
    PAYLOAD_SIZE: "PAYLOAD_SIZE_CHECK",
    NONCE: "NONCE_CHECK",
    PAYLOAD_HASH: "PAYLOAD_HASH_CHECK",
    SEQUENCE: "SEQUENCE_CHECK",
    SIGNATURE: "SIGNATURE_CHECK",
} as const;

/* ── Protocol Errors ─────────────────────────────────────────────────── */

export const ProtocolError = {
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
    SECRET_MISSING: "SECRET_MISSING",
} as const;

export type ProtocolErrorCode = (typeof ProtocolError)[keyof typeof ProtocolError];
