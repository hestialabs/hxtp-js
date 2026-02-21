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

import type { CryptoProvider } from "../crypto/interface.js";
import type { ValidationResult } from "../types/protocol.js";
import {
    PROTOCOL_VERSION,
    MAX_MESSAGE_AGE_SEC,
    TIMESTAMP_SKEW_SEC,
    MAX_PAYLOAD_BYTES,
    ProtocolError,
} from "../types/protocol.js";
import { verifySignatureWithFallback } from "./signing.js";
import type { NonceCache } from "./nonce.js";

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

function pass(): ValidationResult {
    return { ok: true, code: "", reason: "", rotated: false };
}

function fail(code: string, reason: string): ValidationResult {
    return { ok: false, code, reason, rotated: false };
}

/**
 * Validate an inbound message through the client-side pipeline.
 */
export async function validateMessage(
    msg: ValidatableMessage,
    opts: ValidationOptions,
): Promise<ValidationResult> {
    const maxAge = opts.maxMessageAgeSec ?? MAX_MESSAGE_AGE_SEC;
    const skew = opts.timestampSkewSec ?? TIMESTAMP_SKEW_SEC;
    const now = opts.nowMs ?? Date.now();

    /* ── 1. Version ──────────────────────────────────────── */
    const version = msg.version || msg.protocol_version || "";
    if (version !== PROTOCOL_VERSION) {
        return fail(ProtocolError.VERSION_MISMATCH, `Unsupported version: ${version}`);
    }

    /* ── 2. Timestamp Freshness ──────────────────────────── */
    const ts = typeof msg.timestamp === "number" ? msg.timestamp : 0;
    const nowSec = Math.floor(now / 1000);

    let tsSec = ts;
    if (ts > 1_000_000_000_000) {
        tsSec = Math.floor(ts / 1000);
    }

    const ageSec = nowSec - tsSec;

    if (ageSec > maxAge) {
        return fail(ProtocolError.TIMESTAMP_EXPIRED, `Message too old: ${ageSec}s`);
    }

    if (tsSec > nowSec + skew) {
        return fail(
            ProtocolError.TIMESTAMP_FUTURE,
            `Message from future: ${tsSec - nowSec}s ahead`,
        );
    }

    /* ── 3. Payload Size ─────────────────────────────────── */
    if (msg.params) {
        const paramsStr = JSON.stringify(msg.params);
        if (paramsStr.length > MAX_PAYLOAD_BYTES) {
            return fail(
                ProtocolError.PAYLOAD_TOO_LARGE,
                `Payload exceeds ${MAX_PAYLOAD_BYTES} bytes`,
            );
        }
    }

    /* ── 4. Nonce ────────────────────────────────────────── */
    if (!msg.nonce) {
        return fail(ProtocolError.NONCE_MISSING, "Missing nonce");
    }

    if (opts.nonceCache) {
        if (opts.nonceCache.check(msg.nonce)) {
            return fail(ProtocolError.NONCE_REUSED, "Nonce already seen (replay)");
        }
    }

    /* ── 5. Payload Hash ─────────────────────────────────── */
    if (msg.payload_hash) {
        const paramsJson = JSON.stringify(msg.params ?? {});
        const computed = await opts.crypto.sha256Hex(paramsJson);

        if (computed !== msg.payload_hash) {
            return fail(ProtocolError.HASH_MISMATCH, "Payload hash mismatch");
        }
    }

    /* ── 6. Signature ────────────────────────────────────── */
    if (!msg.signature) {
        return fail(ProtocolError.SIGNATURE_MISSING, "Missing signature");
    }

    const sigResult = await verifySignatureWithFallback(
        opts.crypto,
        opts.activeSecret,
        opts.previousSecret,
        msg as Required<
            Pick<
                ValidatableMessage,
                | "version"
                | "message_type"
                | "device_id"
                | "tenant_id"
                | "timestamp"
                | "message_id"
                | "nonce"
            >
        > &
            Record<string, unknown>,
        msg.signature,
    );

    if (!sigResult.valid) {
        return fail(ProtocolError.SIGNATURE_INVALID, "HMAC-SHA256 verification failed");
    }

    const result = pass();
    return { ...result, rotated: sigResult.rotated };
}
