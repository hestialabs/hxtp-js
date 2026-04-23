# 🛡️ hxtp-js

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)](https://github.com/hestialabs/hxtp-js)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Environment](https://img.shields.io/badge/env-Browser%20%7C%20Node%20%7C%20Bun-orange.svg)](https://nodejs.org/)
[![Tree-shakeable](https://img.shields.io/badge/tree--shakeable-yes-brightgreen.svg)](https://developer.mozilla.org/en-US/docs/Glossary/Tree_shaking)

**HxTP/3.0** JavaScript/TypeScript Client SDK — A  high-performance implementation of the HMAC-SHA256 signed IoT protocol. Designed for speed, security, and zero runtime dependencies.

---

## 🚀 Key Features

- **⚡ Lightweight**: Zero runtime dependencies. Tree-shakeable ESM build.
- **🔐 Hardened Security**: Full 6-step client-side validation pipeline. Mandatory HMAC-SHA256 signatures.
- **🌐 Universal**: Works in **Browser**, **Node.js 18+**, **Bun**, **Deno**, and **React Native**.
- **🛡️ Anti-Replay**: Integrated nonce generation and replay protection.
- **🔌 Pluggable**: Customizable transport (WebSocket/MQTT) and crypto providers.
- **🧩 TypeScript First**: Native type definitions for a superior developer experience.

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

### Node.js / Bun

```typescript
import { HXTPClient } from "@hestialabs/hxtp-js";

const client = new HXTPClient({
  url: "wss://mqtt.example.com/ws/state",
  tenantId: "your-tenant-uuid",
  deviceId: "your-device-uuid",
  secret: "64-char-hex-secret-here...",
});

client.on("connect", () => console.log("🛡️ HXTP Connected"));
client.on("message", (event) => console.log("📩 Message:", event.parsed));
client.on("error", (event) => console.error("⚠️ Error:", event.code, event.message));

await client.connect();

// Send a signed command
const response = await client.sendCommand({
  action: "set_brightness",
  params: { value: 80 },
});

console.log("✅ Command Sent:", response.messageId);

await client.disconnect();
```

---

## 🏗️ Architecture

The SDK is built with a strictly modular architecture to support diverse environments.

```text
hxtp-js
├── core/           Protocol-agnostic core logic
│   ├── canonical   FROZEN canonical string builder
│   ├── signing     HMAC-SHA256 signature engine
│   ├── validation  6-step client-side validation pipeline
│   ├── envelope    Signed message envelope builder
│   ├── nonce       Replay protection & nonce management
│   └── topics      MQTT topic orchestration
├── crypto/         Environment-aware crypto providers
│   ├── node        Node.js native (node:crypto)
│   ├── web         Web Crypto API (Browser/RN/Deno)
│   └── detect      Intelligent auto-detection
└── transport/      Pluggable transport layer
    └── websocket   Default WebSocket implementation
```

---

## 🔐 Protocol Alignment: MCSS v3.0

This SDK implements HxTP/3.0 with **exact parity** to the Backend and Embedded C++ SDKs.

| Component | Status | Details |
| :--- | :--- | :--- |
| **Canonical String** | ✅ | FROZEN format for cross-platform signature parity. |
| **HMAC-SHA256** | ✅ | Constant-time verification for security. |
| **Dual-Key Rotation** | ✅ | Seamless secret migration window support. |
| **Validation** | ✅ | Strict 6-step client-side security pipeline. |

### Security Constants

| Constant | Value | Description |
| :--- | :--- | :--- |
| `MAX_MESSAGE_AGE_SEC` | 300 | 5-minute message expiry |
| `TIMESTAMP_SKEW_SEC` | 60 | 1-minute future clock skew tolerance |
| `NONCE_TTL_SEC` | 600 | 10-minute nonce persistence |
| `MAX_PAYLOAD_BYTES` | 16,384 | 16 KB payload hard limit |

---

## 📡 Events

```typescript
client.on("connect", () => { /* Connection established */ });
client.on("disconnect", ({ code, reason }) => { /* Connection closed */ });
client.on("message", ({ raw, parsed, timestamp }) => { /* Validated inbound message */ });
client.on("error", ({ code, message, fatal }) => { /* Protocol or transport error */ });
client.on("reconnecting", ({ attempt, delayMs }) => { /* Auto-reconnect status */ });
```

---

## 🛠️ Configuration

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `url` | `string` | - | WebSocket URL of the HXTP Gateway |
| `tenantId` | `string` | - | Your unique Tenant UUID |
| `deviceId` | `string` | - | The target Device UUID |
| `secret` | `string` | - | 64-character hex shared secret |
| `crypto` | `CryptoProvider` | Auto | Override auto-detected crypto backend |
| `autoReconnect` | `boolean` | `true` | Enable automatic reconnection |
| `heartbeatMs` | `number` | `30000` | Heartbeat interval in milliseconds |

---

## 📦 Output Formats

The SDK is shipped in multiple formats to ensure compatibility with all modern toolchains.

| Format | File | Usage |
| :--- | :--- | :--- |
| **ESM** | `dist/*.js` | `import { HXTPClient } from "@hestialabs/hxtp-js"` |
| **CJS** | `dist/*.cjs` | `const { HXTPClient } = require("@hestialabs/hxtp-js")` |
| **Types** | `dist/*.d.ts` | Full TypeScript type definitions |

## 🛠️ Development

```bash
bun install      # Install dependencies
bun run build    # Build ESM/CJS/Types
bun run test     # Run Vitest suite
```

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

Copyright © 2026 **Hestia Labs**
