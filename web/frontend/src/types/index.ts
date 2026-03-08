/** TypeScript types for the Aether Protect web UI. */

export interface MlResult {
  is_threat: boolean;
  confidence: number;
  threat_type: string;
  mitre_attack?: string[];
}

export interface WafResult {
  would_block: boolean;
  checked: boolean;
  matched_rule?: string | null;
  rule_group?: string | null;
  error?: string;
}

export interface Decision {
  action: string;
  reason: string;
  confidence?: number;
  detection_layer?: "ML" | "WAF" | null;
}

export interface ScanResponse {
  text?: string;
  analyzed_text?: string;
  timestamp?: string;
  ml_result?: MlResult;
  waf_result?: WafResult;
  decision?: Decision;
  agent_analysis?: string;  // AI-generated analysis
  model?: "agentcore" | "onnx";  // Which model was used
  // Direct ML response fields
  is_threat?: boolean;
  confidence?: number;
  threat_type?: string;
  error?: string;
}

export interface ScanResult {
  id: string | number;
  input_type: "http" | "curl" | "raw";
  processed_query: string;
  parsed: {
    method: string | null;
    path: string | null;
    query_params: Record<string, string>;
  };
  threat_detected: boolean;
  threat_type: string | null;
  detection_layer?: "ML" | "WAF" | "ONNX" | null;
  result: ScanResponse;
}

export interface ScanRecord {
  id: number;
  timestamp: string;
  raw_request: string;
  input_type: "http" | "curl" | "raw";
  processed_query: string;
  response: ScanResponse;
  threat_detected: boolean;
  threat_type: string | null;
  client_ip: string | null;
}

export interface Stats {
  total_scans: number;
  threats_detected: number;
  by_type: Array<{ threat_type: string; count: number }>;
}
