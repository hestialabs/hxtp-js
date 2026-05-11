/**
 * @file core/client.ts
 * @description HXTPClient — the public API for HxTP protocol communication.
 *
 * Features:
 *   - Ed25519 signed message construction (HxTP/3.1)
 *   - 11-field pipe-delimited canonical string (HxTP/3.1)
 *   - HELLO/HELLO_ACK lifecycle handshake
 *   - ACTIVE-state gating for command/message dispatch
 *   - Bootstrap/enrollment flow
 *   - Pluggable transport (WebSocket default)
 *   - Auto-reconnect with exponential backoff
 *   - Heartbeat keepalive
 *   - Event emitter pattern (connect, disconnect, message, error)
 *   - Inbound message validation
 *
 * No global singletons. No shared mutable state. No implicit caches.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import type { CryptoProvider } from "../crypto/interface.js";
import type { Transport } from "../transport/interface.js";
import type {
    HXTPConfig,
    HXTPEventType,
    HXTPMessageEvent,
    HXTPErrorEvent,
    HXTPEventHandler,
    HXTPCommandPayload,
    HXTPResponse,
} from "../types/client.js";
import { MessageType } from "../types/protocol.js";
import { buildEnvelope } from "./envelope.js";
import { validateMessage } from "./validation.js";
import { NonceCache } from "./nonce.js";
import { detectCrypto, detectReplayDefault } from "../crypto/detect.js";
import { WebSocketTransport } from "../transport/websocket.js";

type LifecycleState = "IDLE" | "HELLO_SENT" | "ACTIVE" | "DISCONNECTED";

type EventMap = {
    connect: void;
    disconnect: { code: number; reason: string };
    message: HXTPMessageEvent;
    error: HXTPErrorEvent;
    reconnecting: { attempt: number; delayMs: number };
};

export class HXTPClient {
    private readonly config: Readonly<HXTPConfig>;
    private transport: Transport | null = null;
    private crypto: CryptoProvider | null = null;
    private nonceCache: NonceCache | null = null;
    private sequence = 0;
    private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private reconnectAttempt = 0;
    private destroyed = false;
    private lifecycle: LifecycleState = "IDLE";

    private readonly listeners = new Map<HXTPEventType, Set<HXTPEventHandler<unknown>>>();

    constructor(config: HXTPConfig) {
        if (!config.url) throw new Error("config.url is required");
        if (!config.tenantId) throw new Error("config.tenantId is required");
        if (!config.deviceId) throw new Error("config.deviceId is required");
        if (!config.clientId) throw new Error("config.clientId is required");
        if (!config.signingKey) throw new Error("config.signingKey is required");
        if (config.signingKey.length !== 64) {
            throw new Error("config.signingKey must be a 64-character hex string");
        }
        this.config = config;
    }

    /** Connect to the server. Sends HELLO and waits for HELLO_ACK. */
    async connect(): Promise<void> {
        if (this.destroyed) throw new Error("Client has been destroyed");

        this.crypto = this.config.crypto ?? (await detectCrypto());

        const replayEnabled = this.config.replayProtection ?? detectReplayDefault();
        if (replayEnabled) {
            this.nonceCache = new NonceCache();
        }

        this.transport = this.config.transport ?? new WebSocketTransport({ url: this.config.url });

        this.transport.onMessage((data) => this.handleMessage(data));
        this.transport.onClose((code, reason) => this.handleClose(code, reason));
        this.transport.onError((err) => this.handleError(err));

        await this.transport.connect();
        this.reconnectAttempt = 0;
        this.lifecycle = "HELLO_SENT";

        await this.sendHello();
    }

    /** Send HELLO message with device identity (public key). */
    private async sendHello(): Promise<void> {
        if (!this.crypto) throw new Error("Crypto provider not initialized");
        const envelope = await buildEnvelope({
            crypto: this.crypto,
            signingKeyHex: this.config.signingKey,
            deviceId: this.config.deviceId,
            tenantId: this.config.tenantId,
            clientId: this.config.clientId,
            messageType: MessageType.HELLO,
            params: {
                public_key: this.config.serverPublicKey,
                descriptor_hash: this.config.deviceId,
            },
            sequence: 0,
        });

        await this.transport!.send(JSON.stringify(envelope));
    }

    /** Disconnect gracefully and release resources. */
    async disconnect(): Promise<void> {
        this.destroyed = true;
        this.lifecycle = "DISCONNECTED";
        this.stopHeartbeat();
        this.stopReconnect();

        if (this.transport) {
            await this.transport.disconnect();
            this.transport = null;
        }

        this.nonceCache?.clear();
    }

    /**
     * Send a signed command to the server.
     *
     * Constructs a fully signed HxTP envelope with:
     *   - Ed25519 signature over 11-field canonical string
     *   - SHA-256 payload hash
     *   - Cryptographic nonce
     *   - Monotonic sequence number
     */
    async sendCommand(payload: HXTPCommandPayload): Promise<HXTPResponse> {
        if (this.lifecycle !== "ACTIVE") {
            throw new Error("Cannot send command: lifecycle is not ACTIVE");
        }
        if (!this.transport || this.transport.state !== "connected") {
            throw new Error("Not connected");
        }
        if (!this.crypto) {
            throw new Error("Crypto provider not initialized");
        }
        if (this.transport instanceof WebSocketTransport) {
            throw new Error(
                "HxTP command execution over WebSocket is not supported by the backend; use REST or MQTT ingress.",
            );
        }

        this.sequence++;

        const envelope = await buildEnvelope({
            crypto: this.crypto,
            signingKeyHex: this.config.signingKey,
            deviceId: payload.deviceId ?? this.config.deviceId,
            tenantId: this.config.tenantId,
            clientId: this.config.clientId,
            messageType: MessageType.COMMAND,
            action: payload.action,
            params: payload.params,
            sequence: this.sequence,
        });

        const json = JSON.stringify(envelope);
        await this.transport.send(json);

        return {
            ok: true,
            messageId: envelope.message_id,
            timestamp: envelope.timestamp,
        };
    }

    /** Register an event listener. */
    on<K extends HXTPEventType>(event: K, handler: HXTPEventHandler<EventMap[K]>): void {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event)!.add(handler as HXTPEventHandler<unknown>);
    }

    /** Remove an event listener. */
    off<K extends HXTPEventType>(event: K, handler: HXTPEventHandler<EventMap[K]>): void {
        this.listeners.get(event)?.delete(handler as HXTPEventHandler<unknown>);
    }

    /** Whether the client is currently connected and ACTIVE. */
    get connected(): boolean {
        return this.lifecycle === "ACTIVE" && this.transport?.state === "connected";
    }

    /** Current monotonic sequence number. */
    get currentSequence(): number {
        return this.sequence;
    }

    /** Current lifecycle state. */
    get currentLifecycle(): LifecycleState {
        return this.lifecycle;
    }

    /* ── Private Methods ──────────────────────────────────────────────── */

    private emit<K extends HXTPEventType>(event: K, data: EventMap[K]): void {
        const handlers = this.listeners.get(event);
        if (!handlers) return;
        for (const handler of handlers) {
            try {
                handler(data);
            } catch {
                /* event handlers must not throw into the client */
            }
        }
    }

    private async handleMessage(raw: string): Promise<void> {
        let parsed: Record<string, unknown>;
        try {
            parsed = JSON.parse(raw) as Record<string, unknown>;
        } catch {
            this.emitError("PARSE_ERROR", "Invalid JSON message", false);
            return;
        }

        // Handle HELLO_ACK before entering ACTIVE
        if (this.lifecycle === "HELLO_SENT") {
            if (parsed.message_type === "hello_ack") {
                this.lifecycle = "ACTIVE";
                this.startHeartbeat();
                this.emit("connect", undefined);
                return;
            }
            this.emitError("HELLO_TIMEOUT", "Expected HELLO_ACK", true);
            return;
        }

        if (this.crypto && this.config.serverPublicKey) {
            const result = await validateMessage(parsed, {
                crypto: this.crypto,
                activePublicKey: this.config.serverPublicKey,
                previousPublicKey: this.config.previousServerPublicKey,
                nonceCache: this.nonceCache ?? undefined,
                maxMessageAgeSec: this.config.maxMessageAgeSec,
                timestampSkewSec: this.config.timestampSkewSec,
            });

            if (!result.ok) {
                this.emitError(result.code, result.reason, false);
                return;
            }
        }

        this.emit("message", {
            raw,
            parsed,
            timestamp: Date.now(),
        });
    }

    private handleClose(code: number, reason: string): void {
        this.lifecycle = "DISCONNECTED";
        this.stopHeartbeat();
        this.emit("disconnect", { code, reason });

        if (!this.destroyed && (this.config.autoReconnect ?? true)) {
            this.scheduleReconnect();
        }
    }

    private handleError(err: Error): void {
        this.emitError("TRANSPORT_ERROR", err.message, false);
    }

    private emitError(code: string, message: string, fatal: boolean): void {
        this.emit("error", { code, message, fatal });
    }

    private startHeartbeat(): void {
        const interval = this.config.heartbeatIntervalMs ?? 30_000;
        this.heartbeatTimer = setInterval(() => {
            if (this.lifecycle === "ACTIVE" && this.crypto) {
                this.sendHeartbeat().catch(() => {});
            }
        }, interval);
    }

    /**
     * Send a signed heartbeat message.
     * No unsigned messages are allowed over an authenticated channel.
     * The heartbeat is a fully signed HxTP envelope with message_type: "heartbeat".
     */
    private async sendHeartbeat(): Promise<void> {
        if (this.lifecycle !== "ACTIVE" || !this.crypto || !this.transport) return;

        this.sequence++;

        const envelope = await buildEnvelope({
            crypto: this.crypto,
            signingKeyHex: this.config.signingKey,
            deviceId: this.config.deviceId,
            tenantId: this.config.tenantId,
            clientId: this.config.clientId,
            messageType: MessageType.HEARTBEAT,
            params: {},
            sequence: this.sequence,
        });

        await this.transport.send(JSON.stringify(envelope));
    }

    private stopHeartbeat(): void {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
        }
    }

    private scheduleReconnect(): void {
        this.reconnectAttempt++;
        const base = this.config.reconnectDelayMs ?? 1000;
        const max = this.config.maxReconnectDelayMs ?? 30_000;
        const delay = Math.min(base * Math.pow(2, this.reconnectAttempt - 1), max);

        this.emit("reconnecting", { attempt: this.reconnectAttempt, delayMs: delay });

        this.reconnectTimer = setTimeout(async () => {
            if (this.destroyed) return;
            try {
                this.lifecycle = "HELLO_SENT";
                await this.transport?.connect();
                this.reconnectAttempt = 0;
                await this.sendHello();
            } catch {
                this.scheduleReconnect();
            }
        }, delay);
    }

    private stopReconnect(): void {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
    }
}
