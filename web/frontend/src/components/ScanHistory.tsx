import { useState, useEffect } from "react";
import { getAuthHeaders } from "../contexts/AuthContext";
import type { ScanRecord, Stats } from "../types";

interface ScanHistoryProps {
  onSelectScan: (scan: ScanRecord) => void;
}

export function ScanHistory({ onSelectScan }: ScanHistoryProps) {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<"all" | "threats">("all");

  useEffect(() => {
    loadData();
  }, [filter]);

  const loadData = async () => {
    try {
      setLoading(true);

      const headers = getAuthHeaders();

      const [scansRes, statsRes] = await Promise.all([
        fetch(`/api/scans?limit=50&threat_only=${filter === "threats"}`, { headers }),
        fetch("/api/stats", { headers })
      ]);

      const scansData = await scansRes.json();
      const statsData = await statsRes.json();

      setScans(scansData.scans || []);
      setStats(statsData);
    } catch (error) {
      console.error("Failed to load history:", error);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const truncate = (text: string, length: number) => {
    if (text.length <= length) return text;
    return text.substring(0, length) + "...";
  };

  return (
    <div>
      {stats && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="value">{stats.total_scans}</div>
            <div className="label">Total Scans</div>
          </div>
          <div className="stat-card danger">
            <div className="value">{stats.threats_detected}</div>
            <div className="label">Threats Detected</div>
          </div>
          <div className="stat-card">
            <div className="value">
              {stats.total_scans > 0
                ? ((stats.threats_detected / stats.total_scans) * 100).toFixed(1)
                : 0}%
            </div>
            <div className="label">Threat Rate</div>
          </div>
        </div>
      )}

      <div className="tabs" style={{ marginBottom: "var(--spacing-md)" }}>
        <button
          className={`tab ${filter === "all" ? "active" : ""}`}
          onClick={() => setFilter("all")}
        >
          All Scans
        </button>
        <button
          className={`tab ${filter === "threats" ? "active" : ""}`}
          onClick={() => setFilter("threats")}
        >
          Threats Only
        </button>
      </div>

      {loading ? (
        <div className="loading">Loading history...</div>
      ) : scans.length === 0 ? (
        <div className="empty-state">
          <p>No scans yet. Run your first scan above!</p>
        </div>
      ) : (
        <div className="history-list">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className={`history-item ${scan.threat_detected ? "threat" : "safe"}`}
              onClick={() => onSelectScan(scan)}
            >
              <div className="history-item-header">
                <span className={`badge ${scan.threat_detected ? "blocked" : "allowed"}`}>
                  {scan.threat_detected ? "BLOCKED" : "ALLOWED"}
                </span>
                {scan.threat_type && (
                  <span className="threat-type">{scan.threat_type}</span>
                )}
                <span className="history-item-time">{formatTime(scan.timestamp)}</span>
              </div>
              <div className="history-item-preview">
                {truncate(scan.raw_request.split("\n")[0], 80)}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
