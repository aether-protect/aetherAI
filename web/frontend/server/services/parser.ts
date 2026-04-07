/**
 * HTTP/Curl Request Parser (TypeScript port)
 *
 * Parses raw HTTP requests and curl commands to extract
 * text components for security threat analysis.
 */

// Headers interesting for security analysis
const INTERESTING_HEADERS = new Set([
  "authorization", "x-auth-token", "x-api-key", "api-key",
  "user-agent", "x-forwarded-for", "x-real-ip",
  "referer", "origin", "cookie", "content-type",
  "x-custom-header", "x-requested-with"
]);

export interface ParsedRequest {
  method: string | null;
  path: string | null;
  queryParams: Record<string, string>;
  headers: Record<string, string>;
  body: string | null;
  clientIp: string | null;
  inputType: "http" | "curl" | "raw";
  combinedText: string;
}

export function detectInputFormat(text: string): "http" | "curl" | "raw" {
  const stripped = text.trim().toLowerCase();

  // Check for curl command
  if (stripped.startsWith("curl ") || stripped.startsWith("curl\t")) {
    return "curl";
  }

  // Check for HTTP request line
  const httpMethods = ["get ", "post ", "put ", "delete ", "patch ", "head ", "options "];
  if (httpMethods.some(m => stripped.startsWith(m))) {
    return "http";
  }

  // Check for HTTP version string
  if (stripped.includes("http/1.") || stripped.includes("http/2")) {
    return "http";
  }

  return "raw";
}

export function parseInput(text: string): ParsedRequest {
  const inputType = detectInputFormat(text);

  switch (inputType) {
    case "http":
      return parseHttpRequest(text);
    case "curl":
      return parseCurlCommand(text);
    default:
      return {
        method: null,
        path: null,
        queryParams: {},
        headers: {},
        body: text,
        clientIp: null,
        inputType: "raw",
        combinedText: text
      };
  }
}

function parseHttpRequest(raw: string): ParsedRequest {
  const result: ParsedRequest = {
    method: null,
    path: null,
    queryParams: {},
    headers: {},
    body: null,
    clientIp: null,
    inputType: "http",
    combinedText: ""
  };

  const lines = raw.split(/\r?\n/);

  if (!lines.length) return result;

  // Parse request line: GET /path?query HTTP/1.1
  const requestMatch = lines[0].match(/^(\w+)\s+([^\s]+)(?:\s+HTTP\/[\d.]+)?/i);

  if (requestMatch) {
    result.method = requestMatch[1].toUpperCase();
    const fullPath = requestMatch[2];

    // Split path and query string
    const [path, queryString] = fullPath.split("?");
    result.path = path;

    if (queryString) {
      for (const param of queryString.split("&")) {
        const [key, value] = param.split("=");
        try {
          result.queryParams[decodeURIComponent(key)] = decodeURIComponent(value || "");
        } catch {
          result.queryParams[key] = value || "";
        }
      }
    }
  }

  // Parse headers until empty line
  let bodyStart = lines.length;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === "") {
      bodyStart = i + 1;
      break;
    }

    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      const headerName = line.substring(0, colonIdx).trim();
      const headerValue = line.substring(colonIdx + 1).trim();
      result.headers[headerName] = headerValue;
    }
  }

  // Parse body
  if (bodyStart < lines.length) {
    result.body = lines.slice(bodyStart).join("\n").trim() || null;
  }

  // Extract client IP from headers
  result.clientIp =
    result.headers["X-Forwarded-For"]?.split(",")[0]?.trim() ||
    result.headers["X-Real-IP"] ||
    null;

  // Build combined text for analysis
  result.combinedText = buildCombinedText(result);

  return result;
}

function parseCurlCommand(cmd: string): ParsedRequest {
  const result: ParsedRequest = {
    method: "GET",
    path: null,
    queryParams: {},
    headers: {},
    body: null,
    clientIp: null,
    inputType: "curl",
    combinedText: ""
  };

  // Normalize line continuations
  const normalized = cmd.replace(/\\\n\s*/g, " ").trim();

  // Tokenize
  const tokens = tokenizeCurl(normalized);

  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    const nextToken = tokens[i + 1];

    switch (token) {
      case "-X":
      case "--request":
        if (nextToken) {
          result.method = nextToken.toUpperCase();
          i += 2;
          continue;
        }
        break;

      case "-H":
      case "--header":
        if (nextToken) {
          const colonIdx = nextToken.indexOf(":");
          if (colonIdx > 0) {
            result.headers[nextToken.substring(0, colonIdx).trim()] =
              nextToken.substring(colonIdx + 1).trim();
          }
          i += 2;
          continue;
        }
        break;

      case "-d":
      case "--data":
      case "--data-raw":
      case "--data-binary":
      case "--data-urlencode":
        if (nextToken) {
          result.body = nextToken;
          if (result.method === "GET") result.method = "POST";
          i += 2;
          continue;
        }
        break;

      case "-u":
      case "--user":
        if (nextToken) {
          try {
            const encoded = Buffer.from(nextToken).toString("base64");
            result.headers["Authorization"] = `Basic ${encoded}`;
          } catch {
            result.headers["Authorization"] = `Basic ${nextToken}`;
          }
          i += 2;
          continue;
        }
        break;

      case "-b":
      case "--cookie":
        if (nextToken) {
          result.headers["Cookie"] = nextToken;
          i += 2;
          continue;
        }
        break;

      case "-A":
      case "--user-agent":
        if (nextToken) {
          result.headers["User-Agent"] = nextToken;
          i += 2;
          continue;
        }
        break;
    }

    // Check for URL
    if (token.startsWith("http://") || token.startsWith("https://")) {
      try {
        const url = new URL(token);
        result.path = url.pathname || "/";
        url.searchParams.forEach((value, key) => {
          result.queryParams[key] = value;
        });
        if (url.host) {
          result.headers["Host"] = url.host;
        }
      } catch {
        result.path = token;
      }
      i++;
      continue;
    }

    // Skip unknown flags
    if (token.startsWith("-")) {
      if (nextToken && !nextToken.startsWith("-")) {
        i += 2;
      } else {
        i++;
      }
      continue;
    }

    i++;
  }

  result.combinedText = buildCombinedText(result);
  return result;
}

function tokenizeCurl(cmd: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inQuote: string | null = null;
  let escape = false;

  for (const char of cmd) {
    if (escape) {
      current += char;
      escape = false;
      continue;
    }

    if (char === "\\") {
      escape = true;
      continue;
    }

    if (inQuote) {
      if (char === inQuote) {
        inQuote = null;
      } else {
        current += char;
      }
    } else if (char === '"' || char === "'") {
      inQuote = char;
    } else if (char === " " || char === "\t") {
      if (current) {
        tokens.push(current);
        current = "";
      }
    } else {
      current += char;
    }
  }

  if (current) tokens.push(current);

  // Skip "curl" command itself
  if (tokens[0]?.toLowerCase() === "curl") {
    return tokens.slice(1);
  }

  return tokens;
}

function buildCombinedText(parsed: ParsedRequest): string {
  const parts: string[] = [];

  if (parsed.path) {
    parts.push(parsed.path);
  }

  for (const value of Object.values(parsed.queryParams)) {
    parts.push(value);
  }

  for (const [name, value] of Object.entries(parsed.headers)) {
    if (INTERESTING_HEADERS.has(name.toLowerCase())) {
      parts.push(value);
    }
  }

  if (parsed.body) {
    parts.push(parsed.body);
  }

  return parts.filter(Boolean).join(" ");
}
