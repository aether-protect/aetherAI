/**
 * SQLite database schema for the local web UI.
 *
 * Stores scan history with:
 * - Original request (HTTP/curl)
 * - Processed query sent to the agent
 * - Full response from the agent
 * - Authenticated user ownership for local parity with Lambda
 */

import { Database } from "bun:sqlite";
import { mkdirSync } from "fs";
import { dirname } from "path";
import { LOCAL_DATABASE_PATH } from "../../shared/appConfig";

export interface ScanRecord {
  id: number;
  timestamp: string;
  raw_request: string;
  input_type: "http" | "curl" | "raw";
  processed_query: string;
  response: string; // JSON string
  threat_detected: number; // 0 or 1 (SQLite boolean)
  threat_type: string | null;
  client_ip: string | null;
  user_id: string;
}

export interface ScanRecordParsed extends Omit<ScanRecord, "response" | "threat_detected"> {
  response: Record<string, unknown>;
  threat_detected: boolean;
}

let db: Database | null = null;

export function getDatabase(dbPath: string = LOCAL_DATABASE_PATH): Database {
  if (db) return db;

  mkdirSync(dirname(dbPath), { recursive: true });
  db = new Database(dbPath, { create: true });

  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      raw_request TEXT NOT NULL,
      input_type TEXT NOT NULL CHECK(input_type IN ('http', 'curl', 'raw')),
      processed_query TEXT NOT NULL,
      response TEXT NOT NULL,
      threat_detected INTEGER NOT NULL DEFAULT 0,
      threat_type TEXT,
      client_ip TEXT,
      user_id TEXT NOT NULL DEFAULT 'anonymous'
    )
  `);

  const columns = db.prepare("PRAGMA table_info(scans)").all() as Array<{ name: string }>;
  if (!columns.some((column) => column.name === "user_id")) {
    db.run("ALTER TABLE scans ADD COLUMN user_id TEXT NOT NULL DEFAULT 'anonymous'");
  }

  // Indexes for common queries
  db.run(`CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_scans_threat ON scans(threat_detected)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(threat_type)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_scans_user_timestamp ON scans(user_id, timestamp DESC)`);

  return db;
}

export function insertScan(
  db: Database,
  scan: Omit<ScanRecord, "id" | "timestamp">
): number {
  const stmt = db.prepare(`
    INSERT INTO scans (raw_request, input_type, processed_query, response, threat_detected, threat_type, client_ip, user_id)
    VALUES ($raw_request, $input_type, $processed_query, $response, $threat_detected, $threat_type, $client_ip, $user_id)
  `);

  const result = stmt.run({
    $raw_request: scan.raw_request,
    $input_type: scan.input_type,
    $processed_query: scan.processed_query,
    $response: scan.response,
    $threat_detected: scan.threat_detected,
    $threat_type: scan.threat_type,
    $client_ip: scan.client_ip,
    $user_id: scan.user_id
  });

  return Number(result.lastInsertRowid);
}

export function getScans(
  db: Database,
  options: {
    limit?: number;
    offset?: number;
    threatOnly?: boolean;
    threatType?: string;
    userId: string;
  }
): ScanRecordParsed[] {
  const { limit = 50, offset = 0, threatOnly = false, threatType, userId } = options;

  let query = "SELECT * FROM scans WHERE user_id = $user_id";
  const params: Record<string, unknown> = {
    $user_id: userId
  };

  if (threatOnly) {
    query += " AND threat_detected = 1";
  }

  if (threatType) {
    query += " AND threat_type = $threat_type";
    params.$threat_type = threatType;
  }

  query += " ORDER BY timestamp DESC LIMIT $limit OFFSET $offset";
  params.$limit = limit;
  params.$offset = offset;

  const stmt = db.prepare(query);
  const rows = stmt.all(params) as ScanRecord[];

  return rows.map(row => ({
    ...row,
    response: JSON.parse(row.response),
    threat_detected: Boolean(row.threat_detected)
  }));
}

export function getScanById(db: Database, id: number, userId: string): ScanRecordParsed | null {
  const stmt = db.prepare("SELECT * FROM scans WHERE id = $id AND user_id = $user_id");
  const row = stmt.get({ $id: id, $user_id: userId }) as ScanRecord | null;

  if (!row) return null;

  return {
    ...row,
    response: JSON.parse(row.response),
    threat_detected: Boolean(row.threat_detected)
  };
}

export function getStats(db: Database, userId: string): {
  total_scans: number;
  threats_detected: number;
  by_type: Array<{ threat_type: string; count: number }>;
} {
  const totals = db.prepare(`
    SELECT
      COUNT(*) as total_scans,
      SUM(threat_detected) as threats_detected
    FROM scans
    WHERE user_id = $user_id
  `).get({ $user_id: userId }) as { total_scans: number; threats_detected: number };

  const byType = db.prepare(`
    SELECT threat_type, COUNT(*) as count
    FROM scans
    WHERE threat_type IS NOT NULL
      AND user_id = $user_id
    GROUP BY threat_type
    ORDER BY count DESC
  `).all({ $user_id: userId }) as Array<{ threat_type: string; count: number }>;

  return {
    total_scans: totals.total_scans || 0,
    threats_detected: totals.threats_detected || 0,
    by_type: byType
  };
}
