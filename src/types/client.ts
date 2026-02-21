/**
 * @file types/client.ts
 * @description Client configuration and event types.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { Transport } from "../transport/interface.js";
import type { CryptoProvider } from "../crypto/interface.js";

/* ── Client Configuration ────────────────────────────────────────────── */

export interface HXTPConfig {
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

/* ── Client Events ───────────────────────────────────────────────────── */

export type HXTPEventType = "connect" | "disconnect" | "message" | "error" | "reconnecting";

export interface HXTPMessageEvent {
    readonly raw: string;
    readonly parsed: Record<string, unknown>;
    readonly timestamp: number;
}

export interface HXTPErrorEvent {
    readonly code: string;
    readonly message: string;
    readonly fatal: boolean;
}

export type HXTPEventHandler<T = unknown> = (event: T) => void;

/* ── Command / Response ──────────────────────────────────────────────── */

export interface HXTPCommandPayload {
    readonly action: string;
    readonly params: Record<string, unknown>;
    readonly deviceId?: string;
}

export interface HXTPResponse {
    readonly ok: boolean;
    readonly messageId: string;
    readonly timestamp: number;
    readonly data?: Record<string, unknown>;
    readonly error?: string;
}
