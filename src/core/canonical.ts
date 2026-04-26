/**
 * @file core/canonical.ts
 * @description FROZEN canonical string builder for HxTP message signatures.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/**
 * Deterministic JSON stringifier (Production Grade).
 * - Lexicographical key sorting
 * - Unicode NFC normalization
 * - Numbers converted to strict decimal strings (avoids IEEE-754 divergence)
 * - Domain Separation: Inject "protocol": "hxtp/1.0"
 */
export function canonicalJson(data: any): string {
    // Top-level object injection for Domain Separation
    if (typeof data === "object" && data !== null && !Array.isArray(data)) {
        if (!data.protocol) {
            data = { ...data, protocol: "hxtp/1.0" };
        }
    }

    const serialize = (val: any): string => {
        if (val === null) return "null";
        if (typeof val === "boolean") return val ? "true" : "false";
        if (typeof val === "number") {
            if (!Number.isFinite(val)) throw new Error("CANONICAL_ERROR: Non-finite number");
            // Bit-perfect cross-platform number strategy: Canonical Decimal String
            const s = val.toFixed(20).replace(/\.?0+$/, "");
            return `"${s}"`;
        }
        if (typeof val === "string") {
            return JSON.stringify(val.normalize("NFC"));
        }
        if (Array.isArray(val)) {
            return "[" + val.map(serialize).join(",") + "]";
        }
        if (typeof val === "object") {
            const keys = Object.keys(val).sort();
            const parts = keys.map((k) => `${JSON.stringify(k)}:${serialize(val[k])}`);
            return "{" + parts.join(",") + "}";
        }
        throw new Error(`CANONICAL_ERROR: Unsupported type ${typeof val}`);
    };

    return serialize(data);
}
