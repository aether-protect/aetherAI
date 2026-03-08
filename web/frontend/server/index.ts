/**
 * Aether Protect web UI backend server.
 *
 * Bun + Hono server with SQLite database.
 * Provides API for security scanning and history.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { getDatabase } from "./db/schema";
import { createAuthRoutes } from "./routes/auth";
import { createScanRoutes } from "./routes/scan";
import { createHistoryRoutes } from "./routes/history";
import { authMiddleware, type AppEnv } from "./services/auth";
import { getAgentHealth } from "./services/python-bridge";
import { APP_NAME, APP_VERSION } from "../shared/appConfig";

const app = new Hono<AppEnv>();

// Initialize database
const db = getDatabase();

// Middleware
app.use("*", logger());
app.use("/api/*", cors({
  origin: ["http://localhost:5173", "http://localhost:3000"],
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"]
}));

// Health check
app.get("/api/health", async (c) => {
  const agentHealth = await getAgentHealth();
  const status = agentHealth.status;
  return c.json({
    status,
    server: "ok",
    version: APP_VERSION,
    agent: status,
    agent_details: agentHealth
  });
});

app.route("/api", createAuthRoutes());
app.use("/api/scan", authMiddleware);
app.use("/api/scans", authMiddleware);
app.use("/api/scans/*", authMiddleware);
app.use("/api/stats", authMiddleware);

// Mount routes
app.route("/api", createScanRoutes(db));
app.route("/api", createHistoryRoutes(db));

// Serve static files in production
app.get("/*", async (c) => {
  const path = c.req.path === "/" ? "/index.html" : c.req.path;
  const file = Bun.file(`./dist${path}`);

  if (await file.exists()) {
    return new Response(file);
  }

  // SPA fallback
  const indexFile = Bun.file("./dist/index.html");
  if (await indexFile.exists()) {
    return new Response(indexFile);
  }

  return c.json({ error: "Not found", hint: "Run 'bun run build' to build frontend" }, 404);
});

const port = parseInt(process.env.PORT || "3000");

console.log(`
  ______                          _      _
 |  _ \\      _   _                | |
 | |_) | ___| |_| |__   ___ _ __  | |_
 |  _ < / _ \\ __| '_ \\ / _ \\ '__| | __|
 | |_) |  __/ |_| | | |  __/ |    | |_
 |____/ \\___|\\__|_| |_|\\___|_|     \\__|
                                  Web UI

  ${APP_NAME}

  Server running on http://localhost:${port}
  API endpoints:
    POST /api/scan     - Analyze a request
    GET  /api/scans    - List scan history
    GET  /api/scans/:id - Get scan details
    GET  /api/stats    - Get statistics
    GET  /api/health   - Health check
`);

export default {
  port,
  fetch: app.fetch
};
