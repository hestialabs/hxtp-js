import { defineConfig } from "tsup";

export default defineConfig([
    {
        entry: {
            index: "src/index.ts",
            "crypto/node": "src/crypto/node.ts",
            "crypto/web": "src/crypto/web.ts",
            "transport/websocket": "src/transport/websocket.ts",
        },
        format: ["esm", "cjs"],
        dts: true,
        splitting: false,
        sourcemap: true,
        clean: true,
        treeshake: true,
        target: "es2022",
        outDir: "dist",
        minify: false,
    },
]);
