import { useState } from "react";

interface ScanFormProps {
  onScan: (request: string) => Promise<void>;
  isLoading: boolean;
}

const PLACEHOLDER = `Enter an HTTP request, curl command, or raw text to analyze...

Examples:

HTTP Request:
GET /api/users?id=1 OR 1=1 HTTP/1.1
Host: example.com
Authorization: Bearer token123

Curl Command:
curl -X POST http://api.example.com/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin'"'"'--"}'

Raw Text:
<script>alert(document.cookie)</script>`;

export function ScanForm({ onScan, isLoading }: ScanFormProps) {
  const [input, setInput] = useState("");
  const [isFocused, setIsFocused] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && !isLoading) {
      await onScan(input);
      setInput(""); // Clear input after submission
    }
  };

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onFocus={() => setIsFocused(true)}
        onBlur={() => setIsFocused(false)}
        placeholder={isFocused ? "" : PLACEHOLDER}
        spellCheck={false}
      />

      <button
        type="submit"
        className="submit-btn"
        disabled={isLoading || !input.trim()}
      >
        {isLoading ? "Analyzing..." : "Analyze Request"}
      </button>
    </form>
  );
}
