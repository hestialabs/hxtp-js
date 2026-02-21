import { C as CryptoProvider } from '../interface-CWp3qyoA.cjs';
export { b as bytesToHex, c as constantTimeEqual, h as hexToBytes } from '../interface-CWp3qyoA.cjs';

/**
 * @file crypto/web.ts
 * @description Browser / React Native crypto provider using Web Crypto API.
 * Works in all environments with `crypto.subtle` (browsers, Expo, Deno).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/** Singleton Web Crypto provider. */
declare const webCrypto: CryptoProvider;
/**
 * Generate a nonce as hex string using Web Crypto.
 */
declare function generateNonce(byteLength?: number): string;

export { generateNonce, webCrypto };
