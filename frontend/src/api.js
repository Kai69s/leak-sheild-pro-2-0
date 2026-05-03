const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with status ${response.status}`);
  }
  return response.json();
}

export function createScan(payload) {
  return request("/api/scans", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function listScans({ q = "", riskLevel = "" } = {}) {
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (riskLevel) params.set("risk_level", riskLevel);
  return request(`/api/scans?${params.toString()}`);
}

export function getScan(id) {
  return request(`/api/scans/${id}`);
}

