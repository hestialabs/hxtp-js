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
    readonly message_type?: string;
    readonly device_id?: string;
    readonly client_id?: string;
    readonly message_id?: string;
    readonly request_id?: string;
    readonly sequence_number?: number | string;
    readonly timestamp?: number | string;
    readonly nonce?: string;
    readonly payload_hash?: string;
    readonly [key: string]: unknown;
}

/**
 * Build a canonical string from a message object.
 *
 * MCSS v3.0 FROZEN FORMAT (10 fields):
 * version|did|cid|mid|rid|seq|ts|nonce|mtype|phash
 */
export function buildCanonical(msg: CanonicalFields): string {
    const parts: string[] = [
        String(msg.version || ""),
        String(msg.device_id || ""),
        String(msg.client_id || ""),
        String(msg.message_id || ""),
        String(msg.request_id || ""),
        String(msg.sequence_number ?? ""),
        String(msg.timestamp || ""),
        String(msg.nonce || ""),
        String(msg.message_type || ""),
        String(msg.payload_hash || ""),
    ];

    // Strict validation: all 10 fields are mandatory in v3.0
    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === "") {
            throw new Error(`CANONICAL_ERROR: Missing mandatory field at index ${i}`);
        }
    }

    return parts.join(CANONICAL_SEPARATOR);
}

/**
 * Parse a canonical string back into named components.
 */
export function parseCanonical(canonical: string): Record<string, string> {
    const parts = canonical.split(CANONICAL_SEPARATOR);
    return {
        version: parts[0] || "",
        device_id: parts[1] || "",
        client_id: parts[2] || "",
        message_id: parts[3] || "",
        request_id: parts[4] || "",
        sequence_number: parts[5] || "",
        timestamp: parts[6] || "",
        nonce: parts[7] || "",
        message_type: parts[8] || "",
        payload_hash: parts[9] || "",
    };
}

/**
 * Validate that a canonical string has exactly 10 non-empty fields.
 */
export function validateCanonical(canonical: string): boolean {
    const parts = canonical.split(CANONICAL_SEPARATOR);
    return parts.length === 10 && parts.every((p) => p.length > 0);
}
