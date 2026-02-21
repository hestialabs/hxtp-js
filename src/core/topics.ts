/**
 * @file core/topics.ts
 * @description MQTT topic builder matching backend Topics.ts.
 *
 * Format: hxtp/{tenantId}/device/{deviceId}/{channel}
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import { Channel, type ChannelValue } from "../types/protocol.js";

/**
 * Build an MQTT topic string for a device channel.
 */
export function buildTopic(tenantId: string, deviceId: string, channel: ChannelValue): string {
    return `hxtp/${tenantId}/device/${deviceId}/${channel}`;
}

/**
 * Build a wildcard subscription topic for a channel.
 */
export function buildWildcard(channel: ChannelValue): string {
    return `hxtp/+/device/+/${channel}`;
}

/**
 * Parse an MQTT topic string into components.
 * Returns null if the topic does not match HxTP format.
 */
export function parseTopic(
    topic: string,
): { tenantId: string; deviceId: string; channel: string } | null {
    const parts = topic.split("/");
    if (parts.length !== 5 || parts[0] !== "hxtp" || parts[2] !== "device") {
        return null;
    }
    return {
        tenantId: parts[1]!,
        deviceId: parts[3]!,
        channel: parts[4]!,
    };
}

export { Channel };
