import { describe, expect, test } from "bun:test";
import { detectInputFormat, parseInput } from "./parser";

describe("parser", () => {
  test("detects curl input", () => {
    expect(detectInputFormat("curl https://example.com")).toBe("curl");
  });

  test("extracts method, path, ip, and body from HTTP input", () => {
    const parsed = parseInput(
      "POST /login?next=/admin HTTP/1.1\nHost: example.com\nX-Forwarded-For: 203.0.113.7\n\n{\"ok\":true}"
    );

    expect(parsed.inputType).toBe("http");
    expect(parsed.method).toBe("POST");
    expect(parsed.path).toBe("/login");
    expect(parsed.queryParams.next).toBe("/admin");
    expect(parsed.clientIp).toBe("203.0.113.7");
    expect(parsed.body).toBe("{\"ok\":true}");
  });

  test("builds combined text from curl command pieces", () => {
    const parsed = parseInput("curl -H 'Authorization: Bearer token' -d 'x=1' https://api.example.com/test");
    expect(parsed.inputType).toBe("curl");
    expect(parsed.combinedText).toContain("/test");
    expect(parsed.combinedText).toContain("Bearer token");
    expect(parsed.combinedText).toContain("x=1");
  });
});
