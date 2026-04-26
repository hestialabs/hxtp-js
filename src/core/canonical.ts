/**
 * @file core/canonical.ts
 * @description FROZEN canonical string builder for HxTP message signatures.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/**
 * Deterministic JSON stringifier.
 * - Lexicographical key sorting
 * - Unicode NFC normalization
 * - Stable number formatting
 * - Explicit null/boolean/UTF-8
 */
export function canonicalJson(data: any): string {
    if (data === null) return "null";
    if (typeof data === "boolean") return data ? "true" : "false";
    if (typeof data === "number") {
        if (!Number.isFinite(data)) throw new Error("CANONICAL_ERROR: Non-finite number");
        const s = data.toString();
        if (s.includes("e")) return data.toFixed(20).replace(/\.?0+$/, "");
        return s;
    }
    if (typeof data === "string") {
        return JSON.stringify(data.normalize("NFC"));
    }
    if (Array.isArray(data)) {
        return "[" + data.map(canonicalJson).join(",") + "]";
    }
    if (typeof data === "object") {
        const keys = Object.keys(data).sort();
        const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(data[k])}`);
        return "{" + parts.join(",") + "}";
    }
    throw new Error(`CANONICAL_ERROR: Unsupported type ${typeof data}`);
}
