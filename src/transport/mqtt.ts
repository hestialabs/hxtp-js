/**
 * @file transport/mqtt.ts
 * @description HxTP-native MQTT transport implementation.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

import mqtt, { type MqttClient } from "mqtt";
import type { Transport, TransportState } from "./interface.js";

export interface MQTTTransportOptions {
    url: string;
    clientId: string;
    username?: string;
    password?: string;
    topicPrefix?: string;
}

/**
 * MQTT Transport for HxTP.
 * Provides deterministic, authority-agnostic communication via an MQTT broker.
 */
export class MQTTTransport implements Transport {
    private client: MqttClient | null = null;
    private _state: TransportState = "disconnected";
    private messageHandler: ((data: string) => void) | null = null;
    private closeHandler: ((code: number, reason: string) => void) | null = null;
    private errorHandler: ((error: Error) => void) | null = null;

    constructor(private readonly options: MQTTTransportOptions) {}

    get state(): TransportState {
        return this._state;
    }

    async connect(): Promise<void> {
        if (this.client) return;

        this._state = "connecting";
        this.client = mqtt.connect(this.options.url, {
            clientId: this.options.clientId,
            username: this.options.username,
            password: this.options.password,
            clean: false, // Resume persistent sessions
            reconnectPeriod: 5000,
        });

        return new Promise((resolve, reject) => {
            this.client!.on("connect", () => {
                this._state = "connected";
                resolve();
            });

            this.client!.on("message", (topic, payload) => {
                if (this.messageHandler) {
                    this.messageHandler(payload.toString());
                }
            });

            this.client!.on("close", () => {
                this._state = "disconnected";
                if (this.closeHandler) {
                    this.closeHandler(0, "MQTT_CLOSED");
                }
            });

            this.client!.on("error", (err) => {
                this._state = "disconnected";
                if (this.errorHandler) {
                    this.errorHandler(err);
                }
                reject(err);
            });
        });
    }

    async disconnect(): Promise<void> {
        if (this.client) {
            await new Promise<void>((resolve) => {
                this.client!.end(false, {}, () => resolve());
            });
            this.client = null;
            this._state = "disconnected";
        }
    }

    async send(data: string): Promise<void> {
        if (!this.client || this._state !== "connected") {
            throw new Error("MQTT_NOT_CONNECTED");
        }

        const parsed = JSON.parse(data);
        const deviceId = parsed.device_id;
        const topic = `${this.options.topicPrefix ?? "hxtp"}/${deviceId}/cmd`;

        return new Promise((resolve, reject) => {
            this.client!.publish(topic, data, { qos: 1 }, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    onMessage(handler: (data: string) => void): void {
        this.messageHandler = handler;
    }

    onClose(handler: (code: number, reason: string) => void): void {
        this.closeHandler = handler;
    }

    onError(handler: (error: Error) => void): void {
        this.errorHandler = handler;
    }
}
