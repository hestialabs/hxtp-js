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
 * - Domain Separation: Inject "protocol": "hxtp/3.0"
 */
export function canonicalJson(data: unknown): string {
    // Top-level object injection for Domain Separation
    if (typeof data === "object" && data !== null && !Array.isArray(data)) {
        const obj = data as Record<string, unknown>;
        if (!obj.protocol) {
            data = { ...obj, protocol: "hxtp/3.0" };
        }
    }

    const serialize = (val: unknown): string => {
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
            const obj = val as Record<string, unknown>;
            const keys = Object.keys(obj).sort();
            const parts = keys.map((k) => `${JSON.stringify(k)}:${serialize(obj[k])}`);
            return "{" + parts.join(",") + "}";
        }
        throw new Error(`CANONICAL_ERROR: Unsupported type ${typeof val}`);
    };

    return serialize(data);
}

/**
 * Legacy wrapper for CanonicalJSON (Production Grade).
 */
export function buildCanonical(data: unknown): string {
    return canonicalJson(data);
}

/**
 * Legacy helper (Deprecated — use JSON parsing).
 */
export function parseCanonical(canonical: string): Record<string, unknown> {
    return JSON.parse(canonical);
}

/**
 * Legacy helper (Deprecated).
 */
export function validateCanonical(canonical: string): boolean {
    try {
        JSON.parse(canonical);
        return true;
    } catch {
        return false;
    }
}
