/**
 * @file transport/websocket.ts
 * @description WebSocket transport for HxTP client.
 * Works in Browser, Node.js 18+ (built-in WebSocket), Bun, Deno, React Native.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { Transport, TransportState } from "./interface.js";

export type { Transport, TransportState } from "./interface.js";

export interface WebSocketTransportOptions {
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
export class WebSocketTransport implements Transport {
    private socket: WebSocket | null = null;
    private messageHandlers: Array<(data: string) => void> = [];
    private closeHandlers: Array<(code: number, reason: string) => void> = [];
    private errorHandlers: Array<(error: Error) => void> = [];
    private _state: TransportState = "disconnected";

    private readonly url: string;
    private readonly protocols?: string | string[];
    private readonly connectTimeoutMs: number;

    constructor(opts: WebSocketTransportOptions) {
        let url = opts.url;
        if (opts.token) {
            const sep = url.includes("?") ? "&" : "?";
            url = `${url}${sep}token=${encodeURIComponent(opts.token)}`;
        }
        this.url = url;
        this.protocols = opts.protocols;
        this.connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
    }

    get state(): TransportState {
        return this._state;
    }

    async connect(): Promise<void> {
        if (this._state === "connected") return;

        this._state = "connecting";

        return new Promise<void>((resolve, reject) => {
            const WS = resolveWebSocket();
            const socket = new WS(this.url, this.protocols);
            this.socket = socket;

            const timeout = setTimeout(() => {
                socket.close();
                this._state = "disconnected";
                reject(
                    new Error(`WebSocket connection timed out after ${this.connectTimeoutMs}ms`),
                );
            }, this.connectTimeoutMs);

            socket.onopen = () => {
                clearTimeout(timeout);
                this._state = "connected";
                resolve();
            };

            socket.onmessage = (event: MessageEvent) => {
                const data = typeof event.data === "string" ? event.data : String(event.data);
                for (const handler of this.messageHandlers) {
                    handler(data);
                }
            };

            socket.onclose = (event: CloseEvent) => {
                clearTimeout(timeout);
                this._state = "disconnected";
                this.socket = null;
                for (const handler of this.closeHandlers) {
                    handler(event.code, event.reason);
                }
            };

            socket.onerror = () => {
                clearTimeout(timeout);
                const err = new Error("WebSocket connection error");
                for (const handler of this.errorHandlers) {
                    handler(err);
                }
                if (this._state === "connecting") {
                    this._state = "disconnected";
                    reject(err);
                }
            };
        });
    }

    async disconnect(): Promise<void> {
        if (!this.socket) return;
        this.socket.close(1000, "Client disconnect");
        this.socket = null;
        this._state = "disconnected";
    }

    async send(data: string): Promise<void> {
        if (!this.socket || this._state !== "connected") {
            throw new Error("WebSocket not connected");
        }
        this.socket.send(data);
    }

    onMessage(handler: (data: string) => void): void {
        this.messageHandlers.push(handler);
    }

    onClose(handler: (code: number, reason: string) => void): void {
        this.closeHandlers.push(handler);
    }

    onError(handler: (error: Error) => void): void {
        this.errorHandlers.push(handler);
    }
}

/**
 * Resolve the WebSocket constructor from the global scope.
 */
function resolveWebSocket(): typeof WebSocket {
    if (typeof globalThis.WebSocket !== "undefined") {
        return globalThis.WebSocket;
    }
    throw new Error(
        "WebSocket not available. For Node.js 18-20, set globalThis.WebSocket " +
            "to a WebSocket implementation (e.g., 'ws' package). Node.js 21+ has built-in WebSocket.",
    );
}
