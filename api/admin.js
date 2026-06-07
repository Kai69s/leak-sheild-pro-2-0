const crypto = require("crypto");
const { clearAuditRecords, listAuditRecords, listAuditUsers } = require("./_auditStore");
const { parseJsonBody, rateLimit, safeCredentialEqual, safeStringEqual, setApiSecurityHeaders } = require("./_security");

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET =
  process.env.ADMIN_SESSION_SECRET || crypto.createHash("sha256").update(`${ADMIN_EMAIL}:${ADMIN_PASSWORD}`).digest("hex");
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
function json(res, status, body) {
  res.status(status).json(body);
}

function setSecurityHeaders(req, res) {
  setApiSecurityHeaders(req, res, { methods: "GET,POST,DELETE,OPTIONS" });
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
  if (!payload || !signature || !safeStringEqual(sign(payload), signature)) return null;
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
    if (!rateLimit(req, res, "admin-login", { limit: 8, windowMs: 15 * 60 * 1000 })) return;
    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
      return json(res, 503, { detail: "Admin credentials are not configured" });
    }
    let body;
    try {
      body = parseJsonBody(req, 8_192);
    } catch (error) {
      return json(res, error.statusCode || 400, { detail: error.message });
    }
    if (!safeCredentialEqual(body.email, ADMIN_EMAIL) || !safeCredentialEqual(body.password, ADMIN_PASSWORD)) {
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
