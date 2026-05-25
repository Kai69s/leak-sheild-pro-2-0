const crypto = require("crypto");
const { clearAuditRecords, listAuditRecords } = require("./_auditStore");

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@leakshield.local";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "LeakShieldAdmin!2026";
const SESSION_SECRET =
  process.env.ADMIN_SESSION_SECRET || crypto.createHash("sha256").update(`${ADMIN_EMAIL}:${ADMIN_PASSWORD}`).digest("hex");
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function json(res, status, body) {
  res.status(status).json(body);
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

module.exports = function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");

  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method === "POST") {
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
      records: listAuditRecords()
    });
  }

  if (req.method === "DELETE") {
    clearAuditRecords();
    return json(res, 200, { ok: true });
  }

  return json(res, 405, { detail: "Method not allowed" });
};
