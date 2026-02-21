import { T as Transport } from './interface-DrtHTySu.cjs';
export { a as TransportState } from './interface-DrtHTySu.cjs';
import { C as CryptoProvider } from './interface-CWp3qyoA.cjs';
export { b as bytesToHex, c as constantTimeEqual, h as hexToBytes } from './interface-CWp3qyoA.cjs';

/**
 * @file types/client.ts
 * @description Client configuration and event types.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

interface HXTPConfig {
    /** HxTP server URL (WebSocket or custom transport endpoint). */
    readonly url: string;
    /** Tenant UUID. */
    readonly tenantId: string;
    /** Device UUID (for device-mode clients). */
    readonly deviceId: string;
    /** Shared secret as hex string (64 chars = 32 bytes). */
    readonly secret: string;
    /** Previous secret for dual-key rotation window (hex string). */
    readonly previousSecret?: string;
    /** Client application identifier (UUID). */
    readonly clientId?: string;
    /** Protocol version override (default: "HxTP/2.2"). */
    readonly protocolVersion?: string;
    /** Transport implementation (default: WebSocket). */
    readonly transport?: Transport;
    /** Crypto provider (default: auto-detected). */
    readonly crypto?: CryptoProvider;
    /** Enable nonce replay cache (default: true in Node, false in browser). */
    readonly replayProtection?: boolean;
    /** Maximum message age in seconds (default: 300). */
    readonly maxMessageAgeSec?: number;
    /** Allowed timestamp skew in seconds (default: 60). */
    readonly timestampSkewSec?: number;
    /** Auto-reconnect on disconnect (default: true). */
    readonly autoReconnect?: boolean;
    /** Reconnect delay in ms (default: 1000). */
    readonly reconnectDelayMs?: number;
    /** Maximum reconnect delay in ms (default: 30000). */
    readonly maxReconnectDelayMs?: number;
    /** Heartbeat interval in ms (default: 30000). */
    readonly heartbeatIntervalMs?: number;
}
type HXTPEventType = "connect" | "disconnect" | "message" | "error" | "reconnecting";
interface HXTPMessageEvent {
    readonly raw: string;
    readonly parsed: Record<string, unknown>;
    readonly timestamp: number;
}
interface HXTPErrorEvent {
    readonly code: string;
    readonly message: string;
    readonly fatal: boolean;
}
type HXTPEventHandler<T = unknown> = (event: T) => void;
interface HXTPCommandPayload {
    readonly action: string;
    readonly params: Record<string, unknown>;
    readonly deviceId?: string;
}
interface HXTPResponse {
    readonly ok: boolean;
    readonly messageId: string;
    readonly timestamp: number;
    readonly data?: Record<string, unknown>;
    readonly error?: string;
}

/**
 * @file core/client.ts
 * @description HXTPClient — the public API for HxTP protocol communication.
 *
 * Features:
 *   - Signed message construction (HMAC-SHA256)
 *   - Pluggable transport (WebSocket default)
 *   - Auto-reconnect with exponential backoff
 *   - Heartbeat keepalive
 *   - Event emitter pattern (connect, disconnect, message, error)
 *   - Inbound message validation
 *
 * No global singletons. No shared mutable state. No implicit caches.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

type EventMap = {
    connect: void;
    disconnect: {
        code: number;
        reason: string;
    };
    message: HXTPMessageEvent;
    error: HXTPErrorEvent;
    reconnecting: {
        attempt: number;
        delayMs: number;
    };
};
declare class HXTPClient {
    private readonly config;
    private transport;
    private crypto;
    private nonceCache;
    private sequence;
    private heartbeatTimer;
    private reconnectTimer;
    private reconnectAttempt;
    private destroyed;
    private readonly listeners;
    constructor(config: HXTPConfig);
    /** Connect to the server. Resolves when the connection is established. */
    connect(): Promise<void>;
    /** Disconnect gracefully and release resources. */
    disconnect(): Promise<void>;
    /**
     * Send a signed command to the server.
     *
     * Constructs a fully signed HxTP envelope with:
     *   - HMAC-SHA256 signature over frozen canonical string
     *   - SHA-256 payload hash
     *   - Cryptographic nonce
     *   - Monotonic sequence number
     */
    sendCommand(payload: HXTPCommandPayload): Promise<HXTPResponse>;
    /** Register an event listener. */
    on<K extends HXTPEventType>(event: K, handler: HXTPEventHandler<EventMap[K]>): void;
    /** Remove an event listener. */
    off<K extends HXTPEventType>(event: K, handler: HXTPEventHandler<EventMap[K]>): void;
    /** Whether the client is currently connected. */
    get connected(): boolean;
    /** Current monotonic sequence number. */
    get currentSequence(): number;
    private emit;
    private handleMessage;
    private handleClose;
    private handleError;
    private emitError;
    private startHeartbeat;
    /**
     * Send a signed heartbeat message.
     * No unsigned messages are allowed over an authenticated channel.
     * The heartbeat is a fully signed HxTP envelope with message_type: "heartbeat".
     */
    private sendHeartbeat;
    private stopHeartbeat;
    private scheduleReconnect;
    private stopReconnect;
}

/**
 * @file core/canonical.ts
 * @description FROZEN canonical string builder for HxTP message signatures.
 *
 * Format: version|message_type|device_id|tenant_id|timestamp|message_id|nonce
 *
 * This format is FROZEN. Any change invalidates ALL signatures across
 * all deployed devices (embedded, backend, and client SDKs).
 *
 * Matches:
 *   - Backend:  src/protocol/Canonical.ts  → BuildCanonical()
 *   - Embedded: lib/HXTP/src/Validation.cpp → build_canonical_string()
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */
interface CanonicalFields {
    readonly version?: string;
    readonly protocol_version?: string;
    readonly message_type?: string;
    readonly device_id?: string;
    readonly tenant_id?: string;
    readonly timestamp?: number | string;
    readonly message_id?: string;
    readonly nonce?: string;
    readonly [key: string]: unknown;
}
/**
 * Build a canonical string from a message object.
 *
 * FROZEN FORMAT — DO NOT MODIFY.
 *
 * Uses `String()` coercion to match backend behavior exactly:
 *   String(Msg.version), String(Msg.message_type), ...
 *
 * The embedded SDK uses `snprintf("%lld", timestamp)` which produces
 * the same decimal representation as `String(timestamp)` in JS.
 */
declare function buildCanonical(msg: CanonicalFields): string;
/**
 * Parse a canonical string back into named components.
 */
declare function parseCanonical(canonical: string): Record<string, string>;
/**
 * Validate that a canonical string has exactly 7 non-empty fields.
 */
declare function validateCanonical(canonical: string): boolean;

/**
 * @file core/signing.ts
 * @description HMAC-SHA256 message signing and verification.
 * Matches backend SecurityModule.ts and embedded Core.cpp signing logic.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

interface SignableMessage {
    readonly version: string;
    readonly message_type: string;
    readonly device_id: string;
    readonly tenant_id: string;
    readonly timestamp: number;
    readonly message_id: string;
    readonly nonce: string;
    readonly [key: string]: unknown;
}
/**
 * Sign a message with HMAC-SHA256 over the canonical string.
 *
 * @param crypto - Crypto provider.
 * @param secretHex - 64-char hex-encoded shared secret.
 * @param msg - Message fields for canonical string construction.
 * @returns 64-char lowercase hex HMAC-SHA256 signature.
 */
declare function signMessage(crypto: CryptoProvider, secretHex: string, msg: SignableMessage): Promise<string>;
/**
 * Verify a message signature using the active secret.
 *
 * @returns `true` if signature is valid, `false` otherwise.
 */
declare function verifySignature(crypto: CryptoProvider, secretHex: string, msg: SignableMessage, signature: string): Promise<boolean>;
/**
 * Verify with dual-key fallback for key rotation windows.
 * Mirrors backend `VerifySignatureWithFallback`.
 *
 * @returns `{ valid, rotated }` — rotated=true means previous key matched.
 */
declare function verifySignatureWithFallback(crypto: CryptoProvider, activeSecretHex: string, previousSecretHex: string | undefined, msg: SignableMessage, signature: string): Promise<{
    valid: boolean;
    rotated: boolean;
}>;

/**
 * @file types/protocol.ts
 * @description HxTP/2.2 protocol type definitions.
 * All types are frozen and aligned with embedded SDK v1.0 + backend.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */
declare const PROTOCOL_VERSION: "HxTP/2.2";
declare const CANONICAL_SEPARATOR: "|";
declare const MAX_MESSAGE_AGE_SEC = 300;
declare const TIMESTAMP_SKEW_SEC = 60;
declare const NONCE_TTL_SEC = 600;
declare const MAX_PAYLOAD_BYTES = 16384;
declare const HMAC_HEX_LENGTH = 64;
declare const SHA256_HEX_LENGTH = 64;
declare const MIN_NONCE_BYTES = 16;
declare const MessageType: {
    readonly STATE: "state";
    readonly COMMAND: "command";
    readonly HEARTBEAT: "heartbeat";
    readonly TELEMETRY: "telemetry";
    readonly OTA: "ota";
    readonly ACK: "ack";
    readonly ERROR: "error";
};
type MessageTypeValue = (typeof MessageType)[keyof typeof MessageType];
declare const Channel: {
    readonly STATE: "state";
    readonly CMD: "cmd";
    readonly CMD_ACK: "cmd_ack";
    readonly HELLO: "hello";
    readonly HEARTBEAT: "heartbeat";
    readonly OTA: "ota";
    readonly OTA_STATUS: "ota_status";
    readonly TELEMETRY: "telemetry";
};
type ChannelValue = (typeof Channel)[keyof typeof Channel];
interface HXTPMessageHeader {
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
interface HXTPEnvelope {
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
interface ValidationResult {
    readonly ok: boolean;
    readonly code: string;
    readonly reason: string;
    readonly rotated: boolean;
}
declare const ValidationStep: {
    readonly VERSION: "VERSION_CHECK";
    readonly TIMESTAMP: "TIMESTAMP_CHECK";
    readonly PAYLOAD_SIZE: "PAYLOAD_SIZE_CHECK";
    readonly NONCE: "NONCE_CHECK";
    readonly PAYLOAD_HASH: "PAYLOAD_HASH_CHECK";
    readonly SEQUENCE: "SEQUENCE_CHECK";
    readonly SIGNATURE: "SIGNATURE_CHECK";
};
declare const ProtocolError: {
    readonly VERSION_MISMATCH: "VERSION_MISMATCH";
    readonly TIMESTAMP_EXPIRED: "TIMESTAMP_EXPIRED";
    readonly TIMESTAMP_FUTURE: "TIMESTAMP_FUTURE";
    readonly PAYLOAD_TOO_LARGE: "PAYLOAD_TOO_LARGE";
    readonly NONCE_MISSING: "NONCE_MISSING";
    readonly NONCE_REUSED: "NONCE_REUSED";
    readonly HASH_MISMATCH: "HASH_MISMATCH";
    readonly SEQUENCE_VIOLATION: "SEQUENCE_VIOLATION";
    readonly SIGNATURE_MISSING: "SIGNATURE_MISSING";
    readonly SIGNATURE_INVALID: "SIGNATURE_INVALID";
    readonly SECRET_MISSING: "SECRET_MISSING";
};
type ProtocolErrorCode = (typeof ProtocolError)[keyof typeof ProtocolError];

/**
 * @file core/envelope.ts
 * @description Constructs signed HxTP message envelopes.
 * Matches backend CommandEngine.ts and embedded Core.cpp build logic.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

interface EnvelopeParams {
    readonly crypto: CryptoProvider;
    readonly secretHex: string;
    readonly deviceId: string;
    readonly tenantId: string;
    readonly clientId?: string;
    readonly messageType: MessageTypeValue;
    readonly params?: Record<string, unknown>;
    readonly sequence?: number;
}
/**
 * Build a fully signed HxTP envelope ready for transmission.
 *
 * Steps:
 *   1. Generate message_id (UUID v4 via random bytes)
 *   2. Generate nonce (16 random bytes, hex-encoded)
 *   3. Compute payload_hash (SHA-256 of JSON.stringify(params))
 *   4. Build canonical string
 *   5. Compute HMAC-SHA256 signature
 *   6. Return complete envelope
 */
declare function buildEnvelope(opts: EnvelopeParams): Promise<HXTPEnvelope>;

/**
 * @file core/nonce.ts
 * @description Nonce generation and replay cache.
 * Nonces are hex-encoded random bytes (min 16 bytes → 32 hex chars).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/**
 * Generate a cryptographic nonce as hex string.
 * Minimum 16 raw bytes → 32 hex characters.
 */
declare function generateNonce(crypto: CryptoProvider, byteLength?: number): string;
/**
 * In-memory nonce replay cache with TTL eviction.
 * Suitable for Node.js long-lived processes.
 * Not suitable for stateless browser tabs (disable via config).
 */
declare class NonceCache {
    private readonly entries;
    private readonly maxSize;
    private readonly ttlMs;
    constructor(maxSize?: number, ttlSec?: number);
    /**
     * Check if a nonce has been seen. Returns `true` if duplicate (replay).
     * Automatically records the nonce if new.
     */
    check(nonce: string): boolean;
    /** Remove expired entries. */
    private evict;
    /** Clear all entries. */
    clear(): void;
    /** Current cache size. */
    get size(): number;
}

/**
 * @file core/validation.ts
 * @description Client-side validation pipeline.
 * Mirrors the 7-step server pipeline where applicable on the client.
 *
 * Server pipeline:
 *   1. Version → 2. Timestamp → 3. Nonce → 4. PayloadHash →
 *   5. Sequence → 6. Signature (with dual-key fallback)
 *
 * Embedded pipeline (superset):
 *   1. Version → 2. Timestamp → 3. PayloadSize → 4. Nonce →
 *   5. PayloadHash → 6. Sequence → 7. Signature
 *
 * Client-side validates inbound messages (from server → client):
 *   1. Version       — matches PROTOCOL_VERSION
 *   2. Timestamp     — within MAX_MESSAGE_AGE_SEC + TIMESTAMP_SKEW_SEC
 *   3. PayloadSize   — within MAX_PAYLOAD_BYTES
 *   4. Nonce         — non-empty; optionally checked against replay cache
 *   5. PayloadHash   — SHA-256 of params matches header
 *   6. Signature     — HMAC-SHA256 with dual-key fallback
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

interface ValidatableMessage {
    readonly version?: string;
    readonly protocol_version?: string;
    readonly message_type?: string;
    readonly device_id?: string;
    readonly tenant_id?: string;
    readonly timestamp?: number;
    readonly message_id?: string;
    readonly nonce?: string;
    readonly payload_hash?: string;
    readonly signature?: string;
    readonly params?: Record<string, unknown>;
    readonly [key: string]: unknown;
}
interface ValidationOptions {
    readonly crypto: CryptoProvider;
    readonly activeSecret: string;
    readonly previousSecret?: string;
    readonly nonceCache?: NonceCache;
    readonly maxMessageAgeSec?: number;
    readonly timestampSkewSec?: number;
    readonly nowMs?: number;
}
/**
 * Validate an inbound message through the client-side pipeline.
 */
declare function validateMessage(msg: ValidatableMessage, opts: ValidationOptions): Promise<ValidationResult>;

/**
 * @file core/topics.ts
 * @description MQTT topic builder matching backend Topics.ts.
 *
 * Format: hxtp/{tenantId}/device/{deviceId}/{channel}
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/**
 * Build an MQTT topic string for a device channel.
 */
declare function buildTopic(tenantId: string, deviceId: string, channel: ChannelValue): string;
/**
 * Build a wildcard subscription topic for a channel.
 */
declare function buildWildcard(channel: ChannelValue): string;
/**
 * Parse an MQTT topic string into components.
 * Returns null if the topic does not match HxTP format.
 */
declare function parseTopic(topic: string): {
    tenantId: string;
    deviceId: string;
    channel: string;
} | null;

/**
 * @file crypto/detect.ts
 * @description Auto-detect the best crypto provider for the current runtime.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/**
 * Detect and return the appropriate CryptoProvider.
 *
 * Priority:
 *   1. Node.js / Bun / Deno with node:crypto → NodeCryptoProvider
 *   2. Browser / React Native with crypto.subtle → WebCryptoProvider
 *   3. Throw — no silent fallback
 */
declare function detectCrypto(): Promise<CryptoProvider>;

export { CANONICAL_SEPARATOR, Channel, type ChannelValue, CryptoProvider, HMAC_HEX_LENGTH, HXTPClient, type HXTPCommandPayload, type HXTPConfig, type HXTPEnvelope, type HXTPErrorEvent, type HXTPEventHandler, type HXTPEventType, type HXTPMessageEvent, type HXTPMessageHeader, type HXTPResponse, MAX_MESSAGE_AGE_SEC, MAX_PAYLOAD_BYTES, MIN_NONCE_BYTES, MessageType, type MessageTypeValue, NONCE_TTL_SEC, NonceCache, PROTOCOL_VERSION, ProtocolError, type ProtocolErrorCode, SHA256_HEX_LENGTH, TIMESTAMP_SKEW_SEC, Transport, type ValidationResult, ValidationStep, buildCanonical, buildEnvelope, buildTopic, buildWildcard, detectCrypto, generateNonce, parseCanonical, parseTopic, signMessage, validateCanonical, validateMessage, verifySignature, verifySignatureWithFallback };
