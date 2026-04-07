import { useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { APP_NAME, APP_TAGLINE } from "../../shared/appConfig";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    const success = await login(username, password);

    if (!success) {
      setError("Invalid username or password");
    }

    setIsLoading(false);
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h1>{APP_NAME}</h1>
        <p className="login-subtitle">{APP_TAGLINE}</p>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              disabled={isLoading}
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              disabled={isLoading}
              autoComplete="current-password"
            />
          </div>

          {error && <div className="login-error">{error}</div>}

          <button
            type="submit"
            className="submit-btn login-btn"
            disabled={isLoading || !username || !password}
          >
            {isLoading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <div className="login-hint">
          <p>Demo accounts:</p>
          <code>admin / admin</code> or <code>demo / demo</code>
        </div>
      </div>
    </div>
  );
}
