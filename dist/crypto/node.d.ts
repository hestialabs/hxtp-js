import { C as CryptoProvider } from '../interface-CWp3qyoA.js';
export { b as bytesToHex, c as constantTimeEqual, h as hexToBytes } from '../interface-CWp3qyoA.js';

/**
 * @file crypto/node.ts
 * @description Node.js / Bun / Deno crypto provider using native `node:crypto`.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/** Singleton Node.js crypto provider. */
declare const nodeCrypto: CryptoProvider;
/**
 * Constant-time comparison using Node.js `timingSafeEqual`.
 * Preferred over the platform-agnostic version when available.
 * Uses static ESM import — no CJS require() leakage.
 */
declare function nodeConstantTimeEqual(a: string, b: string): boolean;
/**
 * Generate a nonce as hex string (min 16 raw bytes → 32 hex chars).
 */
declare function generateNonce(byteLength?: number): string;

export { generateNonce, nodeConstantTimeEqual, nodeCrypto };
