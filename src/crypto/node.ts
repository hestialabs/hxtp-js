/**
 * @file crypto/node.ts
 * @description Node.js / Bun / Deno crypto provider using native `node:crypto`.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import {
    createHmac,
    createHash,
    randomBytes as nodeRandomBytes,
    timingSafeEqual,
    sign as nodeSign,
    verify as nodeVerify,
    createPrivateKey,
    createPublicKey,
} from "node:crypto";
import type { CryptoProvider } from "./interface.js";
import { bytesToHex } from "./interface.js";

export { constantTimeEqual, hexToBytes, bytesToHex } from "./interface.js";

class NodeCryptoProvider implements CryptoProvider {
    async signHmacSha256(secret: Uint8Array, data: string): Promise<string> {
        const hmac = createHmac("sha256", secret);
        hmac.update(data, "utf8");
        return hmac.digest("hex");
    }

    async signEd25519(privateKey: Uint8Array, data: string): Promise<string> {
        // Node.js requires PKCS8 wrapping for raw Ed25519 seeds
        const pkcs8Header = Buffer.from([
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
            0x20,
        ]);
        const key = createPrivateKey({
            key: Buffer.concat([pkcs8Header, Buffer.from(privateKey)]),
            format: "der",
            type: "pkcs8",
        });
        const sig = nodeSign(null, Buffer.from(data, "utf8"), key);
        return sig.toString("hex");
    }

    async verifyEd25519(publicKey: Uint8Array, data: string, signature: string): Promise<boolean> {
        // Node.js requires SPKI wrapping for raw Ed25519 public keys
        const spkiHeader = Buffer.from([
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]);
        const key = createPublicKey({
            key: Buffer.concat([spkiHeader, Buffer.from(publicKey)]),
            format: "der",
            type: "spki",
        });
        return nodeVerify(null, Buffer.from(data, "utf8"), key, Buffer.from(signature, "hex"));
    }

    async sha256Hex(data: string): Promise<string> {
        const hash = createHash("sha256");
        hash.update(data, "utf8");
        return hash.digest("hex");
    }

    randomBytes(length: number): Uint8Array {
        return new Uint8Array(nodeRandomBytes(length));
    }
}

/** Singleton Node.js crypto provider. */
export const nodeCrypto: CryptoProvider = new NodeCryptoProvider();

/**
 * Constant-time comparison using Node.js `timingSafeEqual`.
 * Preferred over the platform-agnostic version when available.
 * Uses static ESM import — no CJS require() leakage.
 */
export function nodeConstantTimeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    return timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/**
 * Generate a nonce as hex string (min 16 raw bytes → 32 hex chars).
 */
export function generateNonce(byteLength: number = 16): string {
    const bytes = nodeRandomBytes(byteLength);
    return bytesToHex(new Uint8Array(bytes));
}
