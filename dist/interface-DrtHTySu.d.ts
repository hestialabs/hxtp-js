/**
 * @file transport/interface.ts
 * @description Pluggable transport interface for HxTP client.
 * Implementations: websocket.ts (primary), custom user implementations.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */
type TransportState = "disconnected" | "connecting" | "connected";
interface Transport {
    /** Current connection state. */
    readonly state: TransportState;
    /** Open the connection to the server. */
    connect(): Promise<void>;
    /** Close the connection gracefully. */
    disconnect(): Promise<void>;
    /** Send a string payload. Throws if not connected. */
    send(data: string): Promise<void>;
    /** Register a message handler. */
    onMessage(handler: (data: string) => void): void;
    /** Register a close/disconnect handler. */
    onClose(handler: (code: number, reason: string) => void): void;
    /** Register an error handler. */
    onError(handler: (error: Error) => void): void;
}

export type { Transport as T, TransportState as a };
