import { useState, useCallback } from "react";
import { useAuth, getAuthHeaders } from "./contexts/AuthContext";
import { LoginPage } from "./components/LoginPage";
import { ScanForm } from "./components/ScanForm";
import { ScanResult } from "./components/ScanResult";
import { ScanHistory } from "./components/ScanHistory";
import type { ScanResult as ScanResultType, ScanRecord } from "./types";
import { APP_NAME, APP_TAGLINE } from "../shared/appConfig";

type Tab = "scan" | "history";

function Dashboard() {
  const { username, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>("scan");
  const [isLoading, setIsLoading] = useState(false);
  const [lastResult, setLastResult] = useState<ScanResultType | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = useCallback(async (rawRequest: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders()
        },
        body: JSON.stringify({ raw_request: rawRequest })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Scan failed");
      }

      setLastResult(data);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      setError(message);
      setLastResult(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleSelectScan = useCallback((scan: ScanRecord) => {
    const result: ScanResultType = {
      id: scan.id,
      input_type: scan.input_type,
      processed_query: scan.processed_query,
      parsed: {
        method: null,
        path: null,
        query_params: {}
      },
      threat_detected: scan.threat_detected,
      threat_type: scan.threat_type,
      result: scan.response
    };

    setLastResult(result);
    setActiveTab("scan");
  }, []);

  return (
    <div className="app">
      <header className="header">
        <div style={{ display: "flex", alignItems: "center", gap: "var(--spacing-md)" }}>
          <h1>{APP_NAME}</h1>
          <span className="subtitle">{APP_TAGLINE}</span>
        </div>
        <div className="user-info">
          <span className="username">{username}</span>
          <button className="logout-btn" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      <div className="tabs">
        <button
          className={`tab ${activeTab === "scan" ? "active" : ""}`}
          onClick={() => setActiveTab("scan")}
        >
          Scan
        </button>
        <button
          className={`tab ${activeTab === "history" ? "active" : ""}`}
          onClick={() => setActiveTab("history")}
        >
          History
        </button>
      </div>

      {activeTab === "scan" ? (
        <>
          <ScanForm onScan={handleScan} isLoading={isLoading} />

          {error && (
            <div className="scan-result threat">
              <div className="result-header">
                <span className="badge blocked">ERROR</span>
              </div>
              <p>{error}</p>
            </div>
          )}

          {lastResult && <ScanResult result={lastResult} />}
        </>
      ) : (
        <ScanHistory onSelectScan={handleSelectScan} />
      )}
    </div>
  );
}

export default function App() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return <Dashboard />;
}
