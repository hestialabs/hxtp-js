/**
 * @file crypto/interface.ts
 * @description Unified crypto provider interface.
 * Implementations: node.ts (Node/Bun/Deno), web.ts (Browser/React Native).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */
interface CryptoProvider {
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
declare function constantTimeEqual(a: string, b: string): boolean;
/** Convert Uint8Array to lowercase hex string. */
declare function bytesToHex(bytes: Uint8Array): string;
/** Convert hex string to Uint8Array. */
declare function hexToBytes(hex: string): Uint8Array;

export { type CryptoProvider as C, bytesToHex as b, constantTimeEqual as c, hexToBytes as h };
