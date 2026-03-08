import { createHmac, timingSafeEqual } from "crypto";
import type { MiddlewareHandler } from "hono";
import {
  DEFAULT_AUTH_USERS,
  DEFAULT_TOKEN_EXPIRY_HOURS,
  DEFAULT_TOKEN_SECRET
} from "../../shared/appConfig";

export type AppEnv = {
  Variables: {
    user: string;
  };
};

function parseUsers(usersString: string): Record<string, string> {
  const users: Record<string, string> = {};

  for (const pair of usersString.split(",")) {
    const separatorIndex = pair.indexOf(":");
    if (separatorIndex <= 0) {
      continue;
    }

    const username = pair.slice(0, separatorIndex).trim();
    const password = pair.slice(separatorIndex + 1).trim();
    if (username && password) {
      users[username] = password;
    }
  }

  return users;
}

function getUsers(): Record<string, string> {
  return parseUsers(process.env.AUTH_USERS || DEFAULT_AUTH_USERS);
}

function getTokenSecret(): string {
  return process.env.TOKEN_SECRET || DEFAULT_TOKEN_SECRET;
}

function getTokenExpiryHours(): number {
  const parsed = Number.parseInt(
    process.env.TOKEN_EXPIRY_HOURS || String(DEFAULT_TOKEN_EXPIRY_HOURS),
    10
  );
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_TOKEN_EXPIRY_HOURS;
}

function signPayload(payload: string): string {
  return createHmac("sha256", getTokenSecret()).update(payload).digest("hex").slice(0, 32);
}

function encodeToken(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function decodeToken(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

export function authenticate(username: string, password: string): string | null {
  const users = getUsers();
  return users[username] === password ? username : null;
}

export function createToken(username: string): string {
  const expiresAt = Math.floor(Date.now() / 1000) + getTokenExpiryHours() * 60 * 60;
  const payload = `${username}:${expiresAt}`;
  const signature = signPayload(payload);
  return encodeToken(`${payload}:${signature}`);
}

export function verifyToken(token: string): string | null {
  try {
    const decoded = decodeToken(token);
    const parts = decoded.split(":");
    if (parts.length !== 3) {
      return null;
    }

    const [username, expiresAtRaw, signature] = parts;
    const expiresAt = Number.parseInt(expiresAtRaw, 10);
    if (!username || !Number.isFinite(expiresAt) || expiresAt < Math.floor(Date.now() / 1000)) {
      return null;
    }

    const expectedSignature = signPayload(`${username}:${expiresAt}`);
    const provided = Buffer.from(signature, "utf8");
    const expected = Buffer.from(expectedSignature, "utf8");
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      return null;
    }

    return getUsers()[username] ? username : null;
  } catch {
    return null;
  }
}

export const authMiddleware: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (c.req.method === "OPTIONS") {
    await next();
    return;
  }

  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const user = verifyToken(authHeader.slice(7));
  if (!user) {
    return c.json({ error: "Invalid or expired token" }, 401);
  }

  c.set("user", user);
  await next();
};
