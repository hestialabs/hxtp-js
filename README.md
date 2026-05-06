# 🛡️ hxtp-js

[![Version](https://img.shields.io/badge/version-1.0.7-blue.svg)](https://github.com/hestialabs/hxtp-js)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Environment](https://img.shields.io/badge/env-Browser%20%7C%20Node%20%7C%20Bun-orange.svg)](https://nodejs.org/)

**HxTP/3.1** JavaScript/TypeScript Client SDK — A high-performance implementation of the HMAC-SHA256 signed IoT protocol. Designed for speed, security, and zero runtime dependencies.

---

## 🚀 Key Features

- **⚡ Lightweight**: Zero runtime dependencies. Tree-shakeable ESM build.
- **🔐 HxTP/3.1 Core**: Pipe-separated framing with mandatory backslash escaping and NFC normalization.
- **📡 Native MQTT**: High-performance transport support via `MQTTTransport`.
- **🌐 Universal**: Works in **Browser**, **Node.js 18+**, **Bun**, **Deno**, and **React Native**.
- **🛡️ Anti-Replay**: Integrated nonce generation and monotonic sequence enforcement.
- **🔌 Pluggable**: Customizable transport (MQTT/REST/WS) and crypto providers.

---

## 📦 Installation

```bash
# bun (recommended)
bun add @hestialabs/hxtp-js

# npm
npm install @hestialabs/hxtp-js
```

---

## ⏱️ Quick Start

### Native MQTT Command Execution

```typescript
import { Client } from "@hestialabs/hxtp-js";
import { MQTTTransport } from "@hestialabs/hxtp-js/transport/mqtt";
import { NodeCryptoProvider } from "@hestialabs/hxtp-js/crypto/node";

const client = new Client({
  url: "https://api.hestialabs.in/api/v1",
  tenantId: "your-tenant-uuid",
  deviceId: "your-device-uuid",
  clientId: "unique-client-id",
  secret: "64-char-hex-secret",
  crypto: new NodeCryptoProvider()
});

// Use native MQTT for sub-millisecond dispatch
const mqtt = new MQTTTransport({ url: "tcp://broker.hestialabs.in:1883" });
client.setTransport(mqtt);

await mqtt.connect();

// Send a signed command via MQTT
const response = await client.sendCommand("light-1", "toggle", { power: true });

console.log("✅ Command Sent:", response.messageId);
```

---

## 🏗️ Architecture

The SDK is built with a strictly modular architecture to support diverse environments.

```text
hxtp-js
├── core/           Protocol-agnostic core logic
│   ├── canonical   HxTP/3.1 Pipe-separated builder
│   ├── signing     HMAC-SHA256 signature engine
│   ├── validation  7-step protocol validation pipeline
│   ├── envelope    Signed message envelope builder
│   └── nonce       Replay protection & nonce management
├── crypto/         Environment-aware crypto providers
│   ├── node        Node.js native (node:crypto)
│   └── web         Web Crypto API (Browser/RN/Deno)
└── transport/      Pluggable transport layer
    ├── mqtt        Native MQTT transport
    └── websocket   Secure WebSocket implementation
```

---

## 🔐 Protocol Alignment: HxTP/3.1

This SDK implements HxTP/3.1 with **bit-perfect parity** to the Go, Python, and Embedded SDKs.

| Component | Status | Details |
| :--- | :--- | :--- |
| **Framing** | ✅ | Pipe-separated (`\|`) with mandatory backslash escaping. |
| **Normalization** | ✅ | Mandatory **Unicode NFC** normalization for all fields. |
| **Numbers** | ✅ | Deterministic decimal strings (up to 20 places). |
| **Compliance** | ✅ | Verified against the cross-language compliance suite. |

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

Copyright © 2026 **Hestia Labs**
run test     # Run Vitest suite
```

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

Copyright © 2026 **Hestia Labs**
