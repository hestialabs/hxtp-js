import { T as Transport, a as TransportState } from '../interface-DrtHTySu.js';

/**
 * @file transport/websocket.ts
 * @description WebSocket transport for HxTP client.
 * Works in Browser, Node.js 18+ (built-in WebSocket), Bun, Deno, React Native.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

interface WebSocketTransportOptions {
    /** WebSocket server URL (ws:// or wss://). */
    readonly url: string;
    /** Authentication token sent as query param. */
    readonly token?: string;
    /** Custom WebSocket protocols. */
    readonly protocols?: string | string[];
    /** Connection timeout in ms (default: 10000). */
    readonly connectTimeoutMs?: number;
}
/**
 * WebSocket transport implementation.
 *
 * Uses the global `WebSocket` constructor available in:
 *   - All modern browsers
 *   - Node.js 21+ (global WebSocket)
 *   - Bun (global WebSocket)
 *   - Deno (global WebSocket)
 *   - React Native (global WebSocket)
 *
 * For Node.js 18-20, pass a WebSocket constructor via
 * `globalThis.WebSocket = require('ws')` or use Node 21+.
 */
declare class WebSocketTransport implements Transport {
    private socket;
    private messageHandlers;
    private closeHandlers;
    private errorHandlers;
    private _state;
    private readonly url;
    private readonly protocols?;
    private readonly connectTimeoutMs;
    constructor(opts: WebSocketTransportOptions);
    get state(): TransportState;
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    send(data: string): Promise<void>;
    onMessage(handler: (data: string) => void): void;
    onClose(handler: (code: number, reason: string) => void): void;
    onError(handler: (error: Error) => void): void;
}

export { Transport, TransportState, WebSocketTransport, type WebSocketTransportOptions };
