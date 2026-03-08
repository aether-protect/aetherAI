import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { getDatabase, getScanById, getScans, getStats, insertScan } from "./schema";

describe("schema", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "aether-protect-db-"));
  const dbPath = join(tempRoot, "nested", "history.db");
  const db = getDatabase(dbPath);

  beforeAll(() => {
    db.run("DELETE FROM scans");
  });

  afterAll(() => {
    db.close();
    rmSync(tempRoot, { recursive: true, force: true });
  });

  test("creates the database directory and stores user-owned scans", () => {
    const aliceId = insertScan(db, {
      raw_request: "GET /admin HTTP/1.1",
      input_type: "http",
      processed_query: "/admin",
      response: JSON.stringify({ decision: { action: "ALLOW" } }),
      threat_detected: 0,
      threat_type: null,
      client_ip: "127.0.0.1",
      user_id: "alice"
    });

    insertScan(db, {
      raw_request: "GET /secrets HTTP/1.1",
      input_type: "http",
      processed_query: "/secrets",
      response: JSON.stringify({ decision: { action: "BLOCK" } }),
      threat_detected: 1,
      threat_type: "path_traversal",
      client_ip: "127.0.0.1",
      user_id: "bob"
    });

    const aliceScans = getScans(db, { userId: "alice" });
    expect(aliceScans).toHaveLength(1);
    expect(aliceScans[0]?.user_id).toBe("alice");

    const aliceScan = getScanById(db, aliceId, "alice");
    expect(aliceScan?.id).toBe(aliceId);
    expect(getScanById(db, aliceId, "bob")).toBeNull();

    const bobStats = getStats(db, "bob");
    expect(bobStats.total_scans).toBe(1);
    expect(bobStats.threats_detected).toBe(1);
  });
});
