/**
 * Scan API Routes
 *
 * POST /api/scan - Analyze a request and save to database
 */

import { Hono } from "hono";
import { Database } from "bun:sqlite";
import { callPythonAgent } from "../services/python-bridge";
import { parseInput, detectInputFormat } from "../services/parser";
import { insertScan } from "../db/schema";
import type { AppEnv } from "../services/auth";

export function createScanRoutes(db: Database) {
  const router = new Hono<AppEnv>();

  // POST /api/scan - Perform a security scan
  router.post("/scan", async (c) => {
    try {
      const body = await c.req.json();
      const { raw_request } = body as { raw_request: string };

      if (!raw_request) {
        return c.json({ error: "raw_request is required" }, 400);
      }

      // Parse the request
      const inputType = detectInputFormat(raw_request);
      const parsed = parseInput(raw_request);
      const processedQuery = parsed.combinedText;
      const user = c.get("user");

      // Call Python agent for ML scan
      const result = await callPythonAgent("scan", processedQuery, parsed.clientIp || undefined);

      // Determine threat status from ML result
      let threatDetected = false;
      let threatType: string | null = null;

      if (result.decision?.action === "BLOCK") {
        threatDetected = true;
        threatType = result.ml_result?.threat_type || "unknown";
      } else if (result.is_threat) {
        // Direct ML response
        threatDetected = true;
        threatType = result.threat_type || "unknown";
      }

      // Save to database
      const scanId = insertScan(db, {
        raw_request,
        input_type: inputType,
        processed_query: processedQuery,
        response: JSON.stringify(result),
        threat_detected: threatDetected ? 1 : 0,
        threat_type: threatType,
        client_ip: parsed.clientIp,
        user_id: user
      });

      // Return result with metadata
      return c.json({
        id: scanId,
        input_type: inputType,
        processed_query: processedQuery,
        parsed: {
          method: parsed.method,
          path: parsed.path,
          query_params: parsed.queryParams
        },
        threat_detected: threatDetected,
        threat_type: threatType,
        result
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return c.json({ error: message }, 500);
    }
  });

  return router;
}
