import Markdown from "react-markdown";
import type { ScanResult as ScanResultType } from "../types";

interface ScanResultProps {
  result: ScanResultType;
}

export function ScanResult({ result }: ScanResultProps) {
  const { threat_detected, threat_type, result: response, parsed } = result;

  // Determine the action and reason
  const action = threat_detected ? "BLOCKED" : "ALLOWED";
  const detectionLayer = response.decision?.detection_layer;
  const reason =
    response.decision?.reason ||
    (response.is_threat ? `AI: ${response.threat_type}` : "No threat detected");

  // Get ML result info
  const mlResult = response.ml_result || (response.is_threat !== undefined ? {
    is_threat: response.is_threat,
    confidence: response.confidence || 0,
    threat_type: response.threat_type || "unknown",
    mitre_attack: []
  } : null);

  // Get WAF result info
  const wafResult = response.waf_result;

  // Get AI analysis
  const agentAnalysis = response.agent_analysis;

  return (
    <div className={`scan-result ${threat_detected ? "threat" : "safe"}`}>
      <div className="result-header">
        <span className={`badge ${threat_detected ? "blocked" : "allowed"}`}>
          {action}
        </span>
        {detectionLayer && (
          <span className={`badge ${detectionLayer === "WAF" ? "waf-badge" : "ml-badge"}`}>
            {detectionLayer === "WAF" ? "WAF Layer" : "ML Layer"}
          </span>
        )}
        {threat_type && <span className="threat-type">{threat_type}</span>}
        {parsed.method && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.875rem" }}>
            {parsed.method} {parsed.path}
          </span>
        )}
      </div>

      <p style={{ color: "var(--color-text-dim)" }}>{reason}</p>

      {/* Two-Layer Defense Results */}
      <div className="defense-layers">
        {/* Layer 1: ML Detection */}
        {mlResult && (
          <div className="result-section layer-section">
            <h4>
              <span className="layer-indicator">Layer 1</span> ML Detection
            </h4>
            <div className="ml-stats">
              <div className="ml-stat">
                <div className="label">Threat</div>
                <div className="value" style={{ color: mlResult.is_threat ? "var(--color-danger)" : "var(--color-success)" }}>
                  {mlResult.is_threat ? "Yes" : "No"}
                </div>
              </div>
              <div className="ml-stat">
                <div className="label">Type</div>
                <div className="value">{mlResult.threat_type}</div>
              </div>
              <div className="ml-stat">
                <div className="label">Confidence</div>
                <div className="value">{(mlResult.confidence * 100).toFixed(1)}%</div>
              </div>
            </div>
            {mlResult.mitre_attack && mlResult.mitre_attack.length > 0 && (
              <div style={{ marginTop: "0.5rem" }}>
                <span className="label">MITRE ATT&CK: </span>
                {mlResult.mitre_attack.map((id, i) => (
                  <span key={id} className="mitre-tag">
                    {id}{i < mlResult.mitre_attack!.length - 1 ? ", " : ""}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Layer 2: WAF Check */}
        {wafResult && (
          <div className="result-section layer-section">
            <h4>
              <span className="layer-indicator layer-2">Layer 2</span> AWS WAF Check
            </h4>
            <div className="ml-stats">
              <div className="ml-stat">
                <div className="label">Checked</div>
                <div className="value">
                  {wafResult.checked ? "Yes" : "No"}
                </div>
              </div>
              <div className="ml-stat">
                <div className="label">Would Block</div>
                <div className="value" style={{ color: wafResult.would_block ? "var(--color-danger)" : "var(--color-success)" }}>
                  {wafResult.would_block ? "Yes" : "No"}
                </div>
              </div>
              {wafResult.matched_rule && (
                <div className="ml-stat">
                  <div className="label">Matched Rule</div>
                  <div className="value">{wafResult.matched_rule}</div>
                </div>
              )}
            </div>
            {wafResult.rule_group && (
              <div style={{ marginTop: "0.5rem" }}>
                <span className="label">Rule Group: </span>
                <span className="waf-rule-group">{wafResult.rule_group}</span>
              </div>
            )}
            {wafResult.error && (
              <div style={{ marginTop: "0.5rem", color: "var(--color-warning)" }}>
                <span className="label">Note: </span>
                <span>{wafResult.error}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {agentAnalysis && (
        <div className="result-section">
          <h4>AI Analysis</h4>
          <div className="agent-analysis markdown-content">
            <Markdown>{agentAnalysis}</Markdown>
          </div>
        </div>
      )}
    </div>
  );
}
