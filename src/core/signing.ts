/**
 * @file core/signing.ts
 * @description HMAC-SHA256 message signing and verification.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { CryptoProvider } from "../crypto/interface.js";
import { constantTimeEqual, hexToBytes } from "../crypto/interface.js";
import { canonicalJson, pipeCanonical } from "./canonical.js";
import { ED25519_SIG_HEX_LENGTH } from "../types/protocol.js";

interface SignableMessage {
    readonly version: string;
    readonly message_type: string;
    readonly device_id: string;
    readonly tenant_id: string;
    readonly client_id: string;
    readonly message_id: string;
    readonly request_id: string;
    readonly sequence_number: number | bigint;
    readonly timestamp: number;
    readonly nonce: string;
    readonly payload_hash: string;
    readonly [key: string]: unknown;
}

/**
 * Sign a message with Ed25519 over the canonical string.
 *
 * @param crypto - Crypto provider.
 * @param privateKeyHex - 64-char hex-encoded private key seed.
 * @param msg - Message fields for canonical string construction.
 * @returns 128-char lowercase hex Ed25519 signature.
 */
export async function signMessage(
    crypto: CryptoProvider,
    privateKeyHex: string,
    msg: SignableMessage,
): Promise<string> {
    if (!privateKeyHex || privateKeyHex.length !== 64) {
        throw new Error("Private key must be a 64-character hex string (32 bytes).");
    }

    const privBytes = hexToBytes(privateKeyHex);
    const signable = { ...msg } as Record<string, unknown>;
    delete signable.signature;

    const canonical =
        signable.version === "HxTP/3.1"
            ? pipeCanonical(signable as Parameters<typeof pipeCanonical>[0])
            : canonicalJson(signable);

    return crypto.signEd25519(privBytes, canonical);
}

/**
 * Verify a message signature using an Ed25519 public key.
 *
 * @returns `true` if signature is valid, `false` otherwise.
 */
export async function verifySignature(
    crypto: CryptoProvider,
    publicKeyHex: string,
    msg: SignableMessage,
    signature: string,
): Promise<boolean> {
    if (!signature || signature.length !== ED25519_SIG_HEX_LENGTH) return false;
    if (!publicKeyHex || publicKeyHex.length !== 64) return false;

    const pubBytes = hexToBytes(publicKeyHex);
    const signable = { ...msg } as Record<string, unknown>;
    delete signable.signature;

    const canonical =
        signable.version === "HxTP/3.1"
            ? pipeCanonical(signable as Parameters<typeof pipeCanonical>[0])
            : canonicalJson(signable);

    return crypto.verifyEd25519(pubBytes, canonical, signature);
}

/**
 * Verify with dual-key fallback for key rotation windows.
 * Mirrors backend `VerifySignatureWithFallback`.
 *
 * @returns `{ valid, rotated }` — rotated=true means previous key matched.
 */
export async function verifySignatureWithFallback(
    crypto: CryptoProvider,
    activePublicKeyHex: string,
    previousPublicKeyHex: string | undefined,
    msg: SignableMessage,
    signature: string,
): Promise<{ valid: boolean; rotated: boolean }> {
    const activeValid = await verifySignature(crypto, activePublicKeyHex, msg, signature);

    if (activeValid) {
        return { valid: true, rotated: false };
    }

    if (previousPublicKeyHex) {
        const prevValid = await verifySignature(crypto, previousPublicKeyHex, msg, signature);

        if (prevValid) {
            return { valid: true, rotated: true };
        }
    }

    return { valid: false, rotated: false };
}
