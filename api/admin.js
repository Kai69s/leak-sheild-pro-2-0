const crypto = require("crypto");
const { clearAuditRecords, listAuditRecords, listAuditUsers } = require("./_auditStore");

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET =
  process.env.ADMIN_SESSION_SECRET || crypto.createHash("sha256").update(`${ADMIN_EMAIL}:${ADMIN_PASSWORD}`).digest("hex");
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const ALLOWED_ORIGINS = new Set([
  "https://leak-shield-pro.vercel.app",
  "http://localhost:5173",
  "http://127.0.0.1:5173"
]);

function json(res, status, body) {
  res.status(status).json(body);
}

function setSecurityHeaders(req, res) {
  const origin = req.headers.origin || "";
  try {
    const hostname = origin ? new URL(origin).hostname : "";
    if (ALLOWED_ORIGINS.has(origin) || /\.vercel\.app$/.test(hostname)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
  } catch {
    // Invalid browser origins are intentionally not allowed for private admin data.
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), payment=(), usb=()");
}

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function sign(payload) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
}

function createToken(email) {
  const payload = base64Url(JSON.stringify({ email, exp: Date.now() + SESSION_TTL_MS }));
  return `${payload}.${sign(payload)}`;
}

function verifyToken(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const [payload, signature] = token.split(".");
  if (!payload || !signature || sign(payload) !== signature) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!decoded.exp || decoded.exp < Date.now()) return null;
    return decoded;
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method === "POST") {
    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
      return json(res, 503, { detail: "Admin credentials are not configured" });
    }
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
    if (body.email !== ADMIN_EMAIL || body.password !== ADMIN_PASSWORD) {
      return json(res, 401, { detail: "Invalid admin credentials" });
    }
    return json(res, 200, { token: createToken(body.email), email: body.email });
  }

  const admin = verifyToken(req);
  if (!admin) return json(res, 401, { detail: "Admin authentication required" });

  if (req.method === "GET") {
    return json(res, 200, {
      admin: admin.email,
      records: await listAuditRecords(),
      users: await listAuditUsers(),
      storage: {
        provider: process.env.BLOB_READ_WRITE_TOKEN || process.env.VERCEL_OIDC_TOKEN ? "vercel_blob_private" : "memory_fallback",
        grouping: "one_user_box_per_browser_session"
      }
    });
  }

  if (req.method === "DELETE") {
    await clearAuditRecords();
    return json(res, 200, { ok: true });
  }

  return json(res, 405, { detail: "Method not allowed" });
};
