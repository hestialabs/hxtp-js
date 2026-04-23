import { describe, it, expect } from "vitest";
import { PROTOCOL_VERSION } from "../src/index.js";

describe("HXTP Protocol", () => {
    it("should have the correct protocol version", () => {
        expect(PROTOCOL_VERSION).toBe("HxTP/3.0");
    });
});
