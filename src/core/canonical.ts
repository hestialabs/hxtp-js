/**
 * @file core/canonical.ts
 * @description FROZEN canonical string builder for HxTP message signatures.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

/**
 * Deterministic JSON stringifier ().
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
 * Canonical params JSON used for payload_hash. This intentionally does not
 * inject a protocol discriminator because params are not a full HxTP envelope.
 */
export function canonicalParamsJson(data: unknown): string {
    const serialize = (val: unknown): string => {
        if (val === undefined || val === null) return "null";
        if (typeof val === "boolean") return val ? "true" : "false";
        if (typeof val === "number") {
            if (!Number.isFinite(val)) throw new Error("CANONICAL_ERROR: Non-finite number");
            let s = val.toFixed(20);
            if (s.includes("e")) s = BigInt(val).toString() + ".00000000000000000000";
            s = s.replace(/\.?0+$/, "");
            if (s === "" || s === "-0") s = "0";
            return `"${s}"`;
        }
        if (typeof val === "string") return JSON.stringify(val.normalize("NFC"));
        if (Array.isArray(val)) return "[" + val.map(serialize).join(",") + "]";
        if (typeof val === "object") {
            const obj = val as Record<string, unknown>;
            return (
                "{" +
                Object.keys(obj)
                    .sort()
                    .map((k) => `${JSON.stringify(k)}:${serialize(obj[k])}`)
                    .join(",") +
                "}"
            );
        }
        throw new Error(`CANONICAL_ERROR: Unsupported type ${typeof val}`);
    };
    return serialize(data ?? {});
}

/**
 * HxTP/3.1 protocol signing canonical: 10 pipe-separated fields.
 */
export function pipeCanonical(msg: {
    readonly version: string;
    readonly device_id: string;
    readonly client_id: string;
    readonly message_id: string;
    readonly request_id: string;
    readonly sequence_number: number | bigint;
    readonly timestamp: number;
    readonly nonce: string;
    readonly message_type: string;
    readonly payload_hash: string;
}): string {
    return [
        msg.version,
        msg.device_id,
        msg.client_id,
        msg.message_id,
        msg.request_id,
        String(msg.sequence_number),
        String(msg.timestamp),
        msg.nonce,
        msg.message_type,
        msg.payload_hash,
    ].join("|");
}

/**
 * Legacy wrapper for CanonicalJSON ().
 */
export function buildCanonical(data: unknown): string {
    if (typeof data === "object" && data !== null && "payload_hash" in data) {
        return pipeCanonical(data as Parameters<typeof pipeCanonical>[0]);
    }
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
