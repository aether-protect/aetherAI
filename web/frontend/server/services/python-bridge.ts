/**
 * Python Bridge - Interface to the local Python agent.
 *
 * Calls the Python CLI via subprocess and translates its JSON output
 * into the shape used by the Bun server.
 */

import { join } from "path";
import { APP_NAME } from "../../shared/appConfig";

export interface ScanResult {
  text?: string;
  analyzed_text?: string;
  ip?: string;
  timestamp?: string;
  ml_result?: {
    is_threat: boolean;
    confidence: number;
    threat_type: string;
    mitre_attack?: string[];
  };
  decision?: {
    action: string;
    reason: string;
    confidence?: number;
  };
  // Direct ML response fields
  is_threat?: boolean;
  confidence?: number;
  threat_type?: string;
  error?: string;
}

// Path to the repo-level Python agent CLI.
const AGENT_PATH = join(import.meta.dir, "../../../..", "agent", "earendel_agent.py");

export async function callPythonAgent(
  command: "scan" | "analyze",
  text: string,
  ip?: string
): Promise<ScanResult> {
  try {
    const args = ["python3", AGENT_PATH, command, text];
    if (command === "scan" && ip) {
      args.push("--ip", ip);
    }

    const proc = Bun.spawn(args, {
      stdout: "pipe",
      stderr: "pipe"
    });

    const [output, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited
    ]);

    if (exitCode !== 0) {
      throw new Error(stderr || `Python agent exited with code ${exitCode}`);
    }

    return JSON.parse(output) as ScanResult;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    return {
      error: message,
      decision: {
        action: "ERROR",
        reason: `Agent error: ${message}`
      }
    };
  }
}

export interface AgentHealth {
  status: "ok" | "degraded" | "unavailable";
  onnx_available?: boolean;
  model_exists?: boolean;
  model_path?: string;
  error?: string;
}

export async function getAgentHealth(): Promise<AgentHealth> {
  try {
    const proc = Bun.spawn(["python3", AGENT_PATH, "health"], {
      stdout: "pipe",
      stderr: "pipe"
    });

    const [output, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited
    ]);

    if (exitCode !== 0) {
      return {
        status: "unavailable",
        error: stderr || `${APP_NAME} agent exited with code ${exitCode}`
      };
    }

    const parsed = JSON.parse(output) as AgentHealth;
    return {
      status: parsed.status || "degraded",
      onnx_available: parsed.onnx_available,
      model_exists: parsed.model_exists,
      model_path: parsed.model_path
    };
  } catch (error) {
    return {
      status: "unavailable",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}
