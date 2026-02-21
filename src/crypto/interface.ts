/**
 * @file crypto/interface.ts
 * @description Unified crypto provider interface.
 * Implementations: node.ts (Node/Bun/Deno), web.ts (Browser/React Native).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

export interface CryptoProvider {
    /**
     * Compute HMAC-SHA256 and return lowercase hex string (64 chars).
     * @param secret - Raw secret bytes.
     * @param data - UTF-8 string to sign.
     */
    signHmacSha256(secret: Uint8Array, data: string): Promise<string>;

    /**
     * Compute SHA-256 hash and return lowercase hex string (64 chars).
     * @param data - UTF-8 string to hash.
     */
    sha256Hex(data: string): Promise<string>;

    /**
     * Generate cryptographically secure random bytes.
     * @param length - Number of bytes.
     */
    randomBytes(length: number): Uint8Array;
}

/**
 * Constant-time string comparison.
 * Safe for comparing HMAC hex digests — prevents timing side-channels.
 * Platform-independent: does NOT rely on crypto.timingSafeEqual.
 */
export function constantTimeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;

    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}

/** Convert Uint8Array to lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
    const hex: string[] = [];
    for (let i = 0; i < bytes.length; i++) {
        hex.push((bytes[i]! >>> 4).toString(16));
        hex.push((bytes[i]! & 0x0f).toString(16));
    }
    return hex.join("");
}

/** Convert hex string to Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string length");
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}
