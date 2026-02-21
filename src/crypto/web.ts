/**
 * @file crypto/web.ts
 * @description Browser / React Native crypto provider using Web Crypto API.
 * Works in all environments with `crypto.subtle` (browsers, Expo, Deno).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { CryptoProvider } from "./interface.js";
import { bytesToHex } from "./interface.js";

export { constantTimeEqual, hexToBytes, bytesToHex } from "./interface.js";

/** Resolve the global crypto object across environments. */
function getSubtle(): SubtleCrypto {
    if (typeof globalThis.crypto?.subtle !== "undefined") {
        return globalThis.crypto.subtle;
    }
    throw new Error("Web Crypto API not available. Use hxtp-js/crypto/node for Node.js.");
}

/** Resolve the global crypto for randomness. */
function getCrypto(): Crypto {
    if (typeof globalThis.crypto !== "undefined") {
        return globalThis.crypto;
    }
    throw new Error("crypto.getRandomValues not available in this environment.");
}

const encoder = new TextEncoder();

class WebCryptoProvider implements CryptoProvider {
    async signHmacSha256(secret: Uint8Array, data: string): Promise<string> {
        const subtle = getSubtle();
        const key = await subtle.importKey(
            "raw",
            secret.buffer as ArrayBuffer,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"],
        );
        const sig = await subtle.sign("HMAC", key, encoder.encode(data));
        return bytesToHex(new Uint8Array(sig));
    }

    async sha256Hex(data: string): Promise<string> {
        const subtle = getSubtle();
        const digest = await subtle.digest("SHA-256", encoder.encode(data));
        return bytesToHex(new Uint8Array(digest));
    }

    randomBytes(length: number): Uint8Array {
        const buf = new Uint8Array(length);
        getCrypto().getRandomValues(buf);
        return buf;
    }
}

/** Singleton Web Crypto provider. */
export const webCrypto: CryptoProvider = new WebCryptoProvider();

/**
 * Generate a nonce as hex string using Web Crypto.
 */
export function generateNonce(byteLength: number = 16): string {
    const bytes = new Uint8Array(byteLength);
    getCrypto().getRandomValues(bytes);
    return bytesToHex(bytes);
}
