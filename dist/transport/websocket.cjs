'use strict';

// src/transport/websocket.ts
var WebSocketTransport = class {
  socket = null;
  messageHandlers = [];
  closeHandlers = [];
  errorHandlers = [];
  _state = "disconnected";
  url;
  protocols;
  connectTimeoutMs;
  constructor(opts) {
    let url = opts.url;
    if (opts.token) {
      const sep = url.includes("?") ? "&" : "?";
      url = `${url}${sep}token=${encodeURIComponent(opts.token)}`;
    }
    this.url = url;
    this.protocols = opts.protocols;
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 1e4;
  }
  get state() {
    return this._state;
  }
  async connect() {
    if (this._state === "connected") return;
    this._state = "connecting";
    return new Promise((resolve, reject) => {
      const WS = resolveWebSocket();
      const socket = new WS(this.url, this.protocols);
      this.socket = socket;
      const timeout = setTimeout(() => {
        socket.close();
        this._state = "disconnected";
        reject(
          new Error(`WebSocket connection timed out after ${this.connectTimeoutMs}ms`)
        );
      }, this.connectTimeoutMs);
      socket.onopen = () => {
        clearTimeout(timeout);
        this._state = "connected";
        resolve();
      };
      socket.onmessage = (event) => {
        const data = typeof event.data === "string" ? event.data : String(event.data);
        for (const handler of this.messageHandlers) {
          handler(data);
        }
      };
      socket.onclose = (event) => {
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
  async disconnect() {
    if (!this.socket) return;
    this.socket.close(1e3, "Client disconnect");
    this.socket = null;
    this._state = "disconnected";
  }
  async send(data) {
    if (!this.socket || this._state !== "connected") {
      throw new Error("WebSocket not connected");
    }
    this.socket.send(data);
  }
  onMessage(handler) {
    this.messageHandlers.push(handler);
  }
  onClose(handler) {
    this.closeHandlers.push(handler);
  }
  onError(handler) {
    this.errorHandlers.push(handler);
  }
};
function resolveWebSocket() {
  if (typeof globalThis.WebSocket !== "undefined") {
    return globalThis.WebSocket;
  }
  throw new Error(
    "WebSocket not available. For Node.js 18-20, set globalThis.WebSocket to a WebSocket implementation (e.g., 'ws' package). Node.js 21+ has built-in WebSocket."
  );
}

exports.WebSocketTransport = WebSocketTransport;
//# sourceMappingURL=websocket.cjs.map
//# sourceMappingURL=websocket.cjs.map