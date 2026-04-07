import { describe, expect, test } from "bun:test";
import { authenticate, createToken, verifyToken } from "./auth";

describe("auth service", () => {
  test("authenticates configured demo users", () => {
    expect(authenticate("admin", "admin")).toBe("admin");
    expect(authenticate("demo", "demo")).toBe("demo");
    expect(authenticate("admin", "wrong-password")).toBeNull();
  });

  test("creates verifiable tokens", () => {
    const token = createToken("admin");
    expect(verifyToken(token)).toBe("admin");
  });

  test("rejects malformed tokens", () => {
    expect(verifyToken("bad-token")).toBeNull();
  });
});
