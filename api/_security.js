const crypto = require("crypto");
const net = require("net");

const DEFAULT_ALLOWED_ORIGINS = [
  "https://leak-sheild-pro-2-0.vercel.app",
  "https://leak-shield-pro.vercel.app",
  "https://leak-shield-pro-mustafa-ahmeds-projects-b0ec78de.vercel.app",
  "https://leak-shield-pro-git-main-mustafa-ahmeds-projects-b0ec78de.vercel.app",
  "http://localhost:5173",
  "http://localhost:5174",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174"
];
const MAX_RATE_LIMIT_BUCKETS = 10_000;
const SESSION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function headerValue(req, name) {
  const value = req.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value || "";
}

function clientIp(req) {
  const candidates = process.env.VERCEL
    ? [headerValue(req, "x-vercel-forwarded-for"), headerValue(req, "x-real-ip")]
    : [req.socket?.remoteAddress || ""];
  for (const candidate of candidates) {
    const value = candidate.split(",")[0].trim().split("%")[0];
    if (net.isIP(value)) return value;
  }
  return "unknown";
}

function sessionId(req) {
  const value = headerValue(req, "x-leakshield-session").trim();
  return SESSION_PATTERN.test(value) ? value.toLowerCase() : "";
}

function allowedOrigins() {
  return new Set(
    [...DEFAULT_ALLOWED_ORIGINS, process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : ""].filter(Boolean)
  );
}

function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (allowedOrigins().has(origin)) return true;
  try {
    const hostname = new URL(origin).hostname;
    return /^leak-shield-[a-z0-9-]+-mustafa-ahmeds-projects-b0ec78de\.vercel\.app$/i.test(hostname);
  } catch {
    return false;
  }
}

function setApiSecurityHeaders(req, res, { methods = "GET,POST,OPTIONS" } = {}) {
  const origin = headerValue(req, "origin");
  if (isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", methods);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-LeakShield-Session");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()");
}

function parseJsonBody(req, maxBytes = 1_000_000) {
  try {
    const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});
    if (Buffer.byteLength(body, "utf8") > maxBytes) {
      const error = new Error("Request body is too large.");
      error.statusCode = 413;
      throw error;
    }
    return typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
  } catch (error) {
    if (error.statusCode) throw error;
    const wrapped = new Error("Invalid JSON request body.");
    wrapped.statusCode = 400;
    throw wrapped;
  }
}

function safeHash(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest();
}

function safeCredentialEqual(a, b) {
  return crypto.timingSafeEqual(safeHash(a), safeHash(b));
}

function safeStringEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function rateLimit(req, res, key, { limit, windowMs }) {
  const bucketKey = `${key}:${clientIp(req)}`;
  const now = Date.now();
  const buckets = (globalThis.__LEAKSHIELD_RATE_LIMITS__ ||= new Map());
  if (buckets.size >= MAX_RATE_LIMIT_BUCKETS) {
    for (const [name, value] of buckets) {
      if (value.resetAt <= now) buckets.delete(name);
    }
    while (buckets.size >= MAX_RATE_LIMIT_BUCKETS) {
      buckets.delete(buckets.keys().next().value);
    }
  }
  const bucket = buckets.get(bucketKey);
  if (!bucket || bucket.resetAt <= now) {
    buckets.set(bucketKey, { count: 1, resetAt: now + windowMs });
    return true;
  }
  bucket.count += 1;
  if (bucket.count <= limit) return true;
  res.setHeader("Retry-After", Math.ceil((bucket.resetAt - now) / 1000));
  res.status(429).json({ detail: "Too many requests. Please wait before trying again." });
  return false;
}

module.exports = {
  clientIp,
  parseJsonBody,
  rateLimit,
  safeCredentialEqual,
  safeStringEqual,
  sessionId,
  setApiSecurityHeaders
};
