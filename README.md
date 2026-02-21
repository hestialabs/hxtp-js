# hxtp-js

> HxTP/2.2 JavaScript/TypeScript Client SDK — HMAC-SHA256 signed IoT protocol.

Production-grade. Tree-shakeable. Zero runtime dependencies.  
Works in **Browser**, **Node.js 18+**, **Bun**, **Deno**, **React Native (Expo)**.

## Installation

```bash
# npm
npm install hxtp-js

# pnpm
pnpm add hxtp-js

# bun
bun add hxtp-js
```

## Quick Start

### Node.js / Bun

```typescript
import { HXTPClient } from "hxtp-js";

const client = new HXTPClient({
  url: "wss://mqtt.example.com/ws/state",
  tenantId: "your-tenant-uuid",
  deviceId: "your-device-uuid",
  secret: "64-char-hex-secret-here...",
});

client.on("connect", () => console.log("Connected"));
client.on("message", (event) => console.log("Message:", event.parsed));
client.on("error", (event) => console.error("Error:", event.code, event.message));

await client.connect();

const response = await client.sendCommand({
  action: "set_brightness",
  params: { value: 80 },
});

console.log("Sent:", response.messageId);

await client.disconnect();
```

### React / Next.js

```tsx
import { HXTPClient } from "hxtp-js";
import { webCrypto } from "hxtp-js/crypto/web";
import { useEffect, useRef } from "react";

function useHXTP(config) {
  const clientRef = useRef(null);

  useEffect(() => {
    const client = new HXTPClient({
      ...config,
      crypto: webCrypto,
      replayProtection: false, // Not needed in browser
    });

    client.connect();
    clientRef.current = client;

    return () => { client.disconnect(); };
  }, []);

  return clientRef;
}
```

### React Native (Expo)

```typescript
import { HXTPClient } from "hxtp-js";
import { webCrypto } from "hxtp-js/crypto/web";

// React Native has global WebSocket and crypto.subtle (via expo-crypto)
const client = new HXTPClient({
  url: "wss://mqtt.example.com/ws/state",
  tenantId: "...",
  deviceId: "...",
  secret: "...",
  crypto: webCrypto,
});

await client.connect();
```

## Architecture

```
hxtp-js
├── core/           Protocol-agnostic core
│   ├── canonical   FROZEN canonical string builder
│   ├── signing     HMAC-SHA256 sign + verify + dual-key rotation
│   ├── validation  6-step client-side validation pipeline
│   ├── envelope    Signed message envelope builder
│   ├── nonce       Nonce generation + replay cache
│   └── topics      MQTT topic builder/parser
├── crypto/         Environment-aware crypto
│   ├── interface   CryptoProvider interface + constantTimeEqual
│   ├── node        Node.js native crypto (node:crypto)
│   ├── web         Web Crypto API (browser/RN/Deno)
│   └── detect      Auto-detection
├── transport/      Pluggable transport
│   ├── interface   Transport interface
│   └── websocket   WebSocket implementation
└── types/          TypeScript type definitions
```

## Crypto Providers

| Environment    | Provider              | Import                          |
| -------------- | --------------------- | ------------------------------- |
| Node.js 18+   | `node:crypto`         | Auto-detected or `hxtp-js/crypto/node` |
| Bun            | `node:crypto`         | Auto-detected                   |
| Deno           | Web Crypto            | Auto-detected                   |
| Browser        | `crypto.subtle`       | Auto-detected or `hxtp-js/crypto/web` |
| React Native   | `crypto.subtle`       | `hxtp-js/crypto/web`      |

Auto-detection runs on `connect()`. Override via `config.crypto`:

```typescript
import { nodeCrypto } from "hxtp-js/crypto/node";

const client = new HXTPClient({
  ...config,
  crypto: nodeCrypto,
});
```

## Custom Transport

```typescript
import type { Transport } from "hxtp-js";

class MQTTTransport implements Transport {
  state: "disconnected" | "connecting" | "connected" = "disconnected";

  async connect() { /* ... */ }
  async disconnect() { /* ... */ }
  async send(data: string) { /* ... */ }
  onMessage(handler: (data: string) => void) { /* ... */ }
  onClose(handler: (code: number, reason: string) => void) { /* ... */ }
  onError(handler: (error: Error) => void) { /* ... */ }
}

const client = new HXTPClient({
  ...config,
  transport: new MQTTTransport(),
});
```

## Protocol Alignment

This SDK implements HxTP/2.2 with **exact parity** to:

| Component         | Canonical String | HMAC-SHA256 | Dual-Key Rotation | Validation Pipeline |
| ----------------- | ---------------- | ----------- | ------------------ | ------------------- |
| **JS SDK** (this) | ✅               | ✅          | ✅                 | ✅ (6-step client)  |
| Backend Server    | ✅               | ✅          | ✅                 | ✅ (7-step server)  |
| Embedded C++ SDK  | ✅               | ✅          | ✅                 | ✅ (7-step device)  |

### Canonical String Format (FROZEN)

```
{version}|{message_type}|{device_id}|{tenant_id}|{timestamp}|{message_id}|{nonce}
```

- **7 fields**, pipe-separated
- **No field reordering**
- **No extra fields**
- Timestamp: `String()` coercion (matches backend `String(Msg.timestamp)` and embedded `snprintf("%lld", ts)`)

### Security Constants

| Constant              | Value  | Description                  |
| --------------------- | ------ | ---------------------------- |
| `MAX_MESSAGE_AGE_SEC` | 300    | 5-minute message expiry      |
| `TIMESTAMP_SKEW_SEC`  | 60     | 1-minute future clock skew   |
| `NONCE_TTL_SEC`       | 600    | 10-minute nonce TTL          |
| `MAX_PAYLOAD_BYTES`   | 16,384 | 16 KB payload hard limit     |
| `MIN_NONCE_BYTES`     | 16     | Minimum nonce entropy        |

## Events

```typescript
client.on("connect", () => { /* connected */ });
client.on("disconnect", ({ code, reason }) => { /* disconnected */ });
client.on("message", ({ raw, parsed, timestamp }) => { /* inbound message */ });
client.on("error", ({ code, message, fatal }) => { /* protocol/transport error */ });
client.on("reconnecting", ({ attempt, delayMs }) => { /* auto-reconnect */ });
```

## Configuration

```typescript
interface HXTPConfig {
  url: string;                    // WebSocket URL
  tenantId: string;               // Tenant UUID
  deviceId: string;               // Device UUID
  secret: string;                 // 64-char hex shared secret
  previousSecret?: string;        // For key rotation window
  clientId?: string;              // Client application ID
  protocolVersion?: string;       // Default: "HxTP/2.2"
  transport?: Transport;          // Default: WebSocket
  crypto?: CryptoProvider;        // Default: auto-detected
  replayProtection?: boolean;     // Default: true (Node) / false (browser)
  maxMessageAgeSec?: number;      // Default: 300
  timestampSkewSec?: number;      // Default: 60
  autoReconnect?: boolean;        // Default: true
  reconnectDelayMs?: number;      // Default: 1000
  maxReconnectDelayMs?: number;   // Default: 30000
  heartbeatIntervalMs?: number;   // Default: 30000
}
```

## Building

```bash
npm run build        # ESM + CJS + .d.ts
npm test             # Run all tests
npm run typecheck    # TypeScript strict check
```

## Output Formats

| Format | File           | Usage                        |
| ------ | -------------- | ---------------------------- |
| ESM    | `dist/*.js`    | `import { HXTPClient } from "hxtp-js"` |
| CJS    | `dist/*.cjs`   | `const { HXTPClient } = require("hxtp-js")` |
| Types  | `dist/*.d.ts`  | TypeScript type definitions   |

## Versioning

- SDK version tracks HxTP protocol version
- Breaking protocol changes = major version bump
- Canonical string format is **permanently frozen**

## License

MIT — Copyright (c) 2026 Hestia Labs
