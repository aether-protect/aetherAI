/**
 * History API Routes
 *
 * GET /api/scans - List scan history
 * GET /api/scans/:id - Get single scan
 * GET /api/stats - Get aggregate statistics
 */

import { Hono } from "hono";
import { Database } from "bun:sqlite";
import { getScans, getScanById, getStats } from "../db/schema";
import type { AppEnv } from "../services/auth";

export function createHistoryRoutes(db: Database) {
  const router = new Hono<AppEnv>();

  // GET /api/scans - List scans with pagination and filtering
  router.get("/scans", (c) => {
    const limit = parseInt(c.req.query("limit") || "50");
    const offset = parseInt(c.req.query("offset") || "0");
    const threatOnly = c.req.query("threat_only") === "true";
    const threatType = c.req.query("threat_type");
    const user = c.get("user");

    const scans = getScans(db, {
      limit,
      offset,
      threatOnly,
      threatType: threatType || undefined,
      userId: user
    });

    return c.json({
      scans,
      pagination: {
        limit,
        offset,
        count: scans.length
      }
    });
  });

  // GET /api/scans/:id - Get single scan by ID
  router.get("/scans/:id", (c) => {
    const id = parseInt(c.req.param("id"));

    if (isNaN(id)) {
      return c.json({ error: "Invalid scan ID" }, 400);
    }

    const user = c.get("user");
    const scan = getScanById(db, id, user);

    if (!scan) {
      return c.json({ error: "Scan not found" }, 404);
    }

    return c.json(scan);
  });

  // GET /api/stats - Get aggregate statistics
  router.get("/stats", (c) => {
    const user = c.get("user");
    const stats = getStats(db, user);
    return c.json(stats);
  });

  return router;
}
