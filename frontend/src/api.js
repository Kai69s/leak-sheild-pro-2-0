const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  (typeof window !== "undefined" && window.location.hostname === "localhost" ? "http://localhost:8000" : "");
const HISTORY_KEY = "leakshield.scanHistory";
const DETAIL_KEY = "leakshield.scanDetails";
const ADMIN_TOKEN_KEY = "leakshield.adminToken";

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
  }).then((scan) => {
    saveScan(scan);
    return scan;
  });
}

export function listScans({ q = "", riskLevel = "" } = {}) {
  const local = readHistory().filter((scan) => {
    const matchesQuery = !q || scan.source_name.toLowerCase().includes(q.toLowerCase());
    const matchesLevel = !riskLevel || scan.overall_level === riskLevel;
    return matchesQuery && matchesLevel;
  });
  if (local.length) return Promise.resolve(local);

  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (riskLevel) params.set("risk_level", riskLevel);
  return request(`/api/scans?${params.toString()}`).catch(() => []);
}

export function getScan(id) {
  const details = readDetails();
  if (details[id]) return Promise.resolve(details[id]);
  return request(`/api/scans/${id}`);
}

export function adminLogin(email, password) {
  return request("/api/admin", {
    method: "POST",
    body: JSON.stringify({ email, password })
  }).then((session) => {
    localStorage.setItem(ADMIN_TOKEN_KEY, session.token);
    return session;
  });
}

export function adminToken() {
  return localStorage.getItem(ADMIN_TOKEN_KEY) || "";
}

export function adminLogout() {
  localStorage.removeItem(ADMIN_TOKEN_KEY);
}

export function fetchAdminAudit(token = adminToken()) {
  return request("/api/admin", {
    headers: { Authorization: `Bearer ${token}` }
  });
}

export function clearAdminAudit(token = adminToken()) {
  return request("/api/admin", {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` }
  });
}

function readHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function readDetails() {
  try {
    return JSON.parse(localStorage.getItem(DETAIL_KEY) || "{}");
  } catch {
    return {};
  }
}

function saveScan(scan) {
  if (typeof localStorage === "undefined" || !scan?.id) return;
  const details = readDetails();
  details[scan.id] = scan;
  localStorage.setItem(DETAIL_KEY, JSON.stringify(details));

  const historyItem = {
    id: scan.id,
    source_name: scan.source_name,
    overall_score: scan.overall_score,
    overall_level: scan.overall_level,
    finding_count: scan.finding_count,
    created_at: scan.created_at
  };
  const history = [historyItem, ...readHistory().filter((item) => item.id !== scan.id)].slice(0, 50);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
}
