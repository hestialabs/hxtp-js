/**
 * @file core/envelope.ts
 * @description Constructs signed HxTP message envelopes.
 * Matches backend CommandEngine.ts and embedded Core.cpp build logic.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { CryptoProvider } from "../crypto/interface.js";
import type { HXTPEnvelope, MessageTypeValue } from "../types/protocol.js";
import { PROTOCOL_VERSION } from "../types/protocol.js";
import { signMessage } from "./signing.js";
import { generateNonce } from "./nonce.js";
import { bytesToHex } from "../crypto/interface.js";

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
export async function buildEnvelope(opts: EnvelopeParams): Promise<HXTPEnvelope> {
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
        nonce,
    };

    const signature = await signMessage(crypto, secretHex, msgFields);

    return {
        ...msgFields,
        client_id: opts.clientId,
        sequence_number: opts.sequence,
        payload_hash: payloadHash,
        signature,
        params,
    };
}

/**
 * Generate a UUID v4 string from random bytes.
 * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 */
function generateUUID(crypto: CryptoProvider): string {
    const bytes = crypto.randomBytes(16);

    /* Set version (4) and variant (10xx) bits per RFC 4122 */
    bytes[6] = (bytes[6]! & 0x0f) | 0x40;
    bytes[8] = (bytes[8]! & 0x3f) | 0x80;

    const hex = bytesToHex(bytes);
    return [
        hex.substring(0, 8),
        hex.substring(8, 12),
        hex.substring(12, 16),
        hex.substring(16, 20),
        hex.substring(20, 32),
    ].join("-");
}
