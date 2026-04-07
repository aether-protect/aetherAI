import { Hono } from "hono";
import { authenticate, createToken, type AppEnv } from "../services/auth";

export function createAuthRoutes() {
  const router = new Hono<AppEnv>();

  router.post("/login", async (c) => {
    try {
      const body = await c.req.json();
      const { username, password } = body as {
        username?: string;
        password?: string;
      };

      if (!username || !password) {
        return c.json({ error: "username and password are required" }, 400);
      }

      const authenticatedUser = authenticate(username, password);
      if (!authenticatedUser) {
        return c.json({ error: "Invalid credentials" }, 401);
      }

      return c.json({
        token: createToken(authenticatedUser),
        username: authenticatedUser
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return c.json({ error: message }, 400);
    }
  });

  return router;
}
