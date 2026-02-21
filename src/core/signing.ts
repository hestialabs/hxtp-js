/**
 * @file core/signing.ts
 * @description HMAC-SHA256 message signing and verification.
 * Matches backend SecurityModule.ts and embedded Core.cpp signing logic.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { CryptoProvider } from "../crypto/interface.js";
import { constantTimeEqual, hexToBytes } from "../crypto/interface.js";
import { buildCanonical } from "./canonical.js";
import { HMAC_HEX_LENGTH } from "../types/protocol.js";

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
export async function signMessage(
    crypto: CryptoProvider,
    secretHex: string,
    msg: SignableMessage,
): Promise<string> {
    if (!secretHex || secretHex.length !== 64) {
        throw new Error("Secret must be a 64-character hex string (32 bytes).");
    }

    const secretBytes = hexToBytes(secretHex);
    const canonical = buildCanonical(msg);
    return crypto.signHmacSha256(secretBytes, canonical);
}

/**
 * Verify a message signature using the active secret.
 *
 * @returns `true` if signature is valid, `false` otherwise.
 */
export async function verifySignature(
    crypto: CryptoProvider,
    secretHex: string,
    msg: SignableMessage,
    signature: string,
): Promise<boolean> {
    if (!signature || signature.length !== HMAC_HEX_LENGTH) return false;
    if (!secretHex) return false;

    const computed = await signMessage(crypto, secretHex, msg);
    return constantTimeEqual(computed, signature);
}

/**
 * Verify with dual-key fallback for key rotation windows.
 * Mirrors backend `VerifySignatureWithFallback`.
 *
 * @returns `{ valid, rotated }` — rotated=true means previous key matched.
 */
export async function verifySignatureWithFallback(
    crypto: CryptoProvider,
    activeSecretHex: string,
    previousSecretHex: string | undefined,
    msg: SignableMessage,
    signature: string,
): Promise<{ valid: boolean; rotated: boolean }> {
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
