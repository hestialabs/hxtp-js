/**
 * @file core/canonical.ts
 * @description FROZEN canonical string builder for HxTP message signatures.
 *
 * Format: version|message_type|device_id|tenant_id|timestamp|message_id|nonce
 *
 * This format is FROZEN. Any change invalidates ALL signatures across
 * all deployed devices (embedded, backend, and client SDKs).
 *
 * Matches:
 *   - Backend:  src/protocol/Canonical.ts  → BuildCanonical()
 *   - Embedded: lib/HXTP/src/Validation.cpp → build_canonical_string()
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import { CANONICAL_SEPARATOR } from "../types/protocol.js";

interface CanonicalFields {
    readonly version?: string;
    readonly protocol_version?: string;
    readonly message_type?: string;
    readonly device_id?: string;
    readonly tenant_id?: string;
    readonly timestamp?: number | string;
    readonly message_id?: string;
    readonly nonce?: string;
    readonly [key: string]: unknown;
}

/**
 * Build a canonical string from a message object.
 *
 * FROZEN FORMAT — DO NOT MODIFY.
 *
 * Uses `String()` coercion to match backend behavior exactly:
 *   String(Msg.version), String(Msg.message_type), ...
 *
 * The embedded SDK uses `snprintf("%lld", timestamp)` which produces
 * the same decimal representation as `String(timestamp)` in JS.
 */
export function buildCanonical(msg: CanonicalFields): string {
    const parts: string[] = [
        String(msg.version || msg.protocol_version || ""),
        String(msg.message_type || ""),
        String(msg.device_id || ""),
        String(msg.tenant_id || ""),
        String(msg.timestamp || ""),
        String(msg.message_id || ""),
        String(msg.nonce || ""),
    ];
    return parts.join(CANONICAL_SEPARATOR);
}

/**
 * Parse a canonical string back into named components.
 */
export function parseCanonical(canonical: string): Record<string, string> {
    const parts = canonical.split(CANONICAL_SEPARATOR);
    return {
        version: parts[0] || "",
        message_type: parts[1] || "",
        device_id: parts[2] || "",
        tenant_id: parts[3] || "",
        timestamp: parts[4] || "",
        message_id: parts[5] || "",
        nonce: parts[6] || "",
    };
}

/**
 * Validate that a canonical string has exactly 7 non-empty fields.
 */
export function validateCanonical(canonical: string): boolean {
    const parts = canonical.split(CANONICAL_SEPARATOR);
    return parts.length === 7 && parts.every((p) => p.length > 0);
}
