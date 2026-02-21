/**
 * @file crypto/detect.ts
 * @description Auto-detect the best crypto provider for the current runtime.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { CryptoProvider } from "./interface.js";

/**
 * Detect and return the appropriate CryptoProvider.
 *
 * Priority:
 *   1. Node.js / Bun / Deno with node:crypto → NodeCryptoProvider
 *   2. Browser / React Native with crypto.subtle → WebCryptoProvider
 *   3. Throw — no silent fallback
 */
export async function detectCrypto(): Promise<CryptoProvider> {
    /* Node.js / Bun / Deno (node compat) */
    if (typeof globalThis.process !== "undefined" && globalThis.process.versions?.node) {
        const mod = await import("./node.js");
        return mod.nodeCrypto;
    }

    /* Deno native */
    if (typeof (globalThis as Record<string, unknown>).Deno !== "undefined") {
        if (typeof globalThis.crypto?.subtle !== "undefined") {
            const mod = await import("./web.js");
            return mod.webCrypto;
        }
    }

    /* Browser / React Native */
    if (typeof globalThis.crypto?.subtle !== "undefined") {
        const mod = await import("./web.js");
        return mod.webCrypto;
    }

    throw new Error(
        "No supported crypto provider found. " +
            "Provide a CryptoProvider via config.crypto, or use " +
            "hxtp-js/crypto/node or hxtp-js/crypto/web.",
    );
}

/**
 * Detect whether replay protection should be enabled by default.
 * Enabled in Node.js/Bun/Deno (server-side), disabled in browsers.
 */
export function detectReplayDefault(): boolean {
    if (typeof globalThis.process !== "undefined" && globalThis.process.versions?.node) {
        return true;
    }
    return false;
}
