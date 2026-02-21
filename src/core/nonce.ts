/**
 * @file core/nonce.ts
 * @description Nonce generation and replay cache.
 * Nonces are hex-encoded random bytes (min 16 bytes → 32 hex chars).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { CryptoProvider } from "../crypto/interface.js";
import { bytesToHex } from "../crypto/interface.js";
import { MIN_NONCE_BYTES, NONCE_TTL_SEC } from "../types/protocol.js";

/**
 * Generate a cryptographic nonce as hex string.
 * Minimum 16 raw bytes → 32 hex characters.
 */
export function generateNonce(
    crypto: CryptoProvider,
    byteLength: number = MIN_NONCE_BYTES,
): string {
    if (byteLength < MIN_NONCE_BYTES) {
        throw new Error(`Nonce must be >= ${MIN_NONCE_BYTES} bytes.`);
    }
    return bytesToHex(crypto.randomBytes(byteLength));
}

/* ── Replay Cache ────────────────────────────────────────────────────── */

interface NonceEntry {
    readonly nonce: string;
    readonly timestampMs: number;
}

/**
 * In-memory nonce replay cache with TTL eviction.
 * Suitable for Node.js long-lived processes.
 * Not suitable for stateless browser tabs (disable via config).
 */
export class NonceCache {
    private readonly entries: NonceEntry[] = [];
    private readonly maxSize: number;
    private readonly ttlMs: number;

    constructor(maxSize: number = 256, ttlSec: number = NONCE_TTL_SEC) {
        this.maxSize = maxSize;
        this.ttlMs = ttlSec * 1000;
    }

    /**
     * Check if a nonce has been seen. Returns `true` if duplicate (replay).
     * Automatically records the nonce if new.
     */
    check(nonce: string): boolean {
        const now = Date.now();
        this.evict(now);

        for (const entry of this.entries) {
            if (entry.nonce === nonce) return true;
        }

        this.entries.push({ nonce, timestampMs: now });

        if (this.entries.length > this.maxSize) {
            this.entries.shift();
        }

        return false;
    }

    /** Remove expired entries. */
    private evict(now: number): void {
        while (this.entries.length > 0 && now - this.entries[0]!.timestampMs > this.ttlMs) {
            this.entries.shift();
        }
    }

    /** Clear all entries. */
    clear(): void {
        this.entries.length = 0;
    }

    /** Current cache size. */
    get size(): number {
        return this.entries.length;
    }
}
