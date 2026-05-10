const crypto = require("crypto");

const MAX_FOLDER_FILES = 80;
const MAX_FILE_BYTES = 120_000;
const MAX_WEBSITE_ASSETS = 12;
const FETCH_TIMEOUT_MS = 7000;

const severityBase = {
  LOW: 20,
  MEDIUM: 45,
  HIGH: 70,
  CRITICAL: 88
};

const highRiskContext = ["production", "prod", "live", "public repo", "github", "exposed", "main branch", "website", "public"];
const lowRiskContext = ["test", "dev", "development", "staging", "sandbox", "local"];

const publicRiskPaths = [
  ".env",
  ".pem",
  ".key",
  "id_rsa",
  "config",
  "settings",
  "firebase",
  "aws",
  "credential",
  "secret"
];

const ignoredFolderParts = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
  "__pycache__",
  ".venv",
  "vendor"
];

const rules = [
  {
    rule_id: "aws-access-key-id",
    secret_type: "AWS Access Key ID",
    severity: "HIGH",
    confidence: 0.95,
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    description: "An AWS access key identifier was exposed.",
    attacker_impact: "Attackers can pair it with a secret key to access AWS APIs.",
    consequence: "Cloud resources, S3 data, IAM permissions, and billing can be abused.",
    remediation: "Disable the access key, rotate credentials, and audit CloudTrail activity."
  },
  {
    rule_id: "generic-api-key",
    secret_type: "API Key",
    severity: "MEDIUM",
    confidence: 0.75,
    pattern: /\b(api[_-]?key|apikey|x-api-key)\b\s*[:=]\s*["']?([A-Za-z0-9_-]{20,120})/gi,
    description: "A generic API key was found in source or configuration text.",
    attacker_impact: "Attackers can call the associated service as the leaked identity.",
    consequence: "Quota abuse, data access, account takeover, or service disruption may occur.",
    remediation: "Rotate the API key, revoke exposed tokens, and move runtime secrets to a managed secret store."
  },
  {
    rule_id: "password-assignment",
    secret_type: "Password",
    severity: "HIGH",
    confidence: 0.7,
    pattern: /\b(password|passwd|pwd|db_password)\b\s*[:=]\s*["']([^"'\s]{8,128})["']?/gi,
    description: "A hardcoded password-like assignment was detected.",
    attacker_impact: "Attackers can authenticate to the protected account or system.",
    consequence: "Credential reuse may expand the breach to databases, apps, or admin panels.",
    remediation: "Change the password, invalidate sessions, remove it from public files and Git history, and load it from environment variables."
  },
  {
    rule_id: "database-url",
    secret_type: "Database URL",
    severity: "CRITICAL",
    confidence: 0.88,
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?):\/\/[^\s"']+:[^\s"']+@[^\s"']+/gi,
    description: "A database connection string containing credentials was exposed.",
    attacker_impact: "Attackers can connect to the database if network access is available.",
    consequence: "Sensitive records may be read, modified, deleted, or ransomed.",
    remediation: "Rotate database credentials, restrict network access, remove the URL from client/public files, and review database logs."
  },
  {
    rule_id: "bearer-token",
    secret_type: "Bearer Token",
    severity: "HIGH",
    confidence: 0.8,
    pattern: /\bbearer\s+([A-Za-z0-9._-]{24,2048})/gi,
    description: "A bearer token was exposed.",
    attacker_impact: "Attackers can replay the token until it expires or is revoked.",
    consequence: "API sessions, user data, and privileged workflows may be compromised.",
    remediation: "Revoke the token, shorten token lifetime, rotate signing keys if needed, and prevent token rendering in public responses."
  },
  {
    rule_id: "jwt-token",
    secret_type: "JWT Token",
    severity: "HIGH",
    confidence: 0.85,
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    description: "A JSON Web Token was found.",
    attacker_impact: "Attackers can impersonate the token subject if the token is valid.",
    consequence: "Application sessions and API authorizations may be abused.",
    remediation: "Revoke the JWT, rotate affected signing secrets, and ensure tokens are never exposed in HTML, JavaScript bundles, or logs."
  },
  {
    rule_id: "private-key-block",
    secret_type: "Private Key",
    severity: "CRITICAL",
    confidence: 0.98,
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    description: "A private cryptographic key block was exposed.",
    attacker_impact: "Attackers can decrypt traffic, sign payloads, or access servers depending on key use.",
    consequence: "SSH access, TLS trust, package signing, or encrypted data may be compromised.",
    remediation: "Replace the key pair, remove it from public access and Git history, rotate all dependent trust, and audit key usage."
  }
];

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function obfuscate(value) {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function lineColumn(content, offset) {
  const prefix = content.slice(0, offset);
  const lines = prefix.split("\n");
  return { line: lines.length, column: lines[lines.length - 1].length + 1 };
}

function levelForScore(score) {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

function isPublicAddress(path = "") {
  const normalized = path.toLowerCase().replaceAll("\\", "/");
  return (
    normalized.startsWith("public/") ||
    normalized.includes("/public/") ||
    normalized.startsWith("static/") ||
    normalized.includes("/static/") ||
    normalized.startsWith("dist/") ||
    normalized.includes("/dist/") ||
    normalized.startsWith("build/") ||
    normalized.includes("/build/") ||
    normalized.startsWith("http://") ||
    normalized.startsWith("https://") ||
    publicRiskPaths.some((part) => normalized.includes(part))
  );
}

function shouldSkipFolderPath(path = "") {
  const normalized = path.toLowerCase().replaceAll("\\", "/");
  return ignoredFolderParts.some((part) => normalized.split("/").includes(part));
}

function scoreFinding(rule, value, content, contextSnippet, metadata, address) {
  let score = severityBase[rule.severity] * rule.confidence;
  const context = `${content} ${contextSnippet} ${JSON.stringify(metadata || {})} ${address || ""}`.toLowerCase();
  const adjustments = [];

  if (highRiskContext.some((term) => context.includes(term))) {
    score += 15;
    adjustments.push("High-risk deployment or public exposure context detected.");
  }
  if (lowRiskContext.some((term) => context.includes(term))) {
    score -= 10;
    adjustments.push("Non-production context reduced the final risk.");
  }
  if (["Private Key", "Database URL"].includes(rule.secret_type)) {
    score += 8;
    adjustments.push("Secret type has direct authentication impact.");
  }
  if (isPublicAddress(address)) {
    score += 12;
    adjustments.push("The finding is located in a public or externally accessible address.");
  }
  if (value.length > 80) {
    score += 3;
    adjustments.push("Long credential material indicates a token or key payload.");
  }

  const bounded = Math.max(0, Math.min(100, Number(score.toFixed(2))));
  return { score: bounded, level: levelForScore(bounded), adjustments };
}

function recommendationFor(findings, mode) {
  if (!findings.length) {
    return {
      priority: "LOW",
      summary: "No exposed secrets were detected in the scanned input.",
      actions: [
        "Keep secrets out of source code and public assets.",
        "Continue using environment variables and server-side secret stores.",
        "Run LeakShield before commits, releases, and public deployments."
      ]
    };
  }

  const levels = findings.map((item) => item.risk_level);
  const priority = levels.includes("CRITICAL") ? "CRITICAL" : levels.includes("HIGH") ? "HIGH" : levels.includes("MEDIUM") ? "MEDIUM" : "LOW";
  const addresses = [...new Set(findings.map((item) => item.file_path || item.source_address || item.source_name).filter(Boolean))].slice(0, 6);
  const actionIntro =
    mode === "website"
      ? "Remove exposed secrets from the public website response and linked static files."
      : "Remove exposed secrets from the listed project files before publishing or committing.";

  return {
    priority,
    summary: `${findings.length} exposure(s) require remediation. Highest priority: ${priority}.`,
    exposed_addresses: addresses,
    actions: [
      actionIntro,
      "Immediately revoke and rotate every exposed credential, token, password, key, or database URL.",
      "Move secrets into server-side environment variables, a vault, or a cloud secret manager.",
      "Remove the secret from Git history and deployment artifacts, then redeploy clean builds.",
      "Review access logs for the affected services and add secret scanning to CI/CD."
    ]
  };
}

function scanDocument({ content, sourceName, filePath, sourceAddress, metadata }) {
  const findings = [];
  const seen = new Set();

  for (const rule of rules) {
    rule.pattern.lastIndex = 0;
    for (const match of content.matchAll(rule.pattern)) {
      const value = match[2] || match[1] || match[0];
      const lowered = value.toLowerCase();
      if (["example", "sample", "dummy", "changeme", "placeholder", "xxxxx"].some((term) => lowered.includes(term))) {
        continue;
      }
      const offset = match.index || 0;
      const key = `${rule.rule_id}:${hash(value)}:${filePath || sourceAddress || sourceName}:${offset}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const pos = lineColumn(content, offset);
      const address = filePath || sourceAddress || sourceName;
      const contextSnippet = content
        .slice(Math.max(0, offset - 90), Math.min(content.length, offset + match[0].length + 90))
        .replace(/\n/g, "\\n");
      const risk = scoreFinding(rule, value, content, contextSnippet, metadata, address);
      const adjustmentText = risk.adjustments.join(" ") || "No contextual adjustment was applied.";
      findings.push({
        id: crypto.randomUUID(),
        rule_id: rule.rule_id,
        secret_type: rule.secret_type,
        severity: rule.severity,
        risk_score: risk.score,
        risk_level: risk.level,
        value_hash: hash(value),
        value_preview: obfuscate(value),
        line_number: pos.line,
        column_start: pos.column,
        column_end: pos.column + match[0].length,
        file_path: filePath || null,
        source_address: sourceAddress || null,
        source_name: sourceName,
        public_accessible: isPublicAddress(address),
        context_snippet: contextSnippet,
        explanation: {
          summary: `${rule.description} Classified as ${risk.level} with score ${risk.score}/100.`,
          attacker_impact: `${rule.attacker_impact} ${adjustmentText}`,
          real_world_consequence: rule.consequence,
          remediation: rule.remediation
        }
      });
    }
  }
  return findings;
}

function aggregateScan({ sourceName, contentHash, findings, mode, metadata }) {
  findings.sort((a, b) => (a.file_path || a.source_address || "").localeCompare(b.file_path || b.source_address || "") || a.line_number - b.line_number);
  const highest = findings.length ? Math.max(...findings.map((item) => item.risk_score)) : 0;
  const overallScore = findings.length ? Math.min(100, Number((highest + Math.min(12, (findings.length - 1) * 3)).toFixed(2))) : 0;
  return {
    id: crypto.randomUUID(),
    mode,
    source_name: sourceName,
    content_hash: contentHash,
    overall_score: overallScore,
    overall_level: levelForScore(overallScore),
    finding_count: findings.length,
    public_exposure_count: findings.filter((item) => item.public_accessible).length,
    scanned_files: metadata.scanned_files || 1,
    scanned_addresses: metadata.scanned_addresses || [],
    recommendation: recommendationFor(findings, mode),
    cache_hit: false,
    created_at: new Date().toISOString(),
    findings
  };
}

function scanText(payload) {
  const content = payload.content || "";
  const findings = scanDocument({
    content,
    sourceName: payload.source_name || "manual-input",
    filePath: payload.source_name || "manual-input",
    metadata: payload.metadata || {}
  });
  return aggregateScan({
    sourceName: payload.source_name || "manual-input",
    contentHash: hash(content),
    findings,
    mode: "text",
    metadata: { scanned_files: 1 }
  });
}

function scanProject(payload) {
  const files = Array.isArray(payload.files) ? payload.files : [];
  const selectedFiles = files
    .filter((file) => file && file.path && typeof file.content === "string" && !shouldSkipFolderPath(file.path))
    .slice(0, MAX_FOLDER_FILES);
  const findings = [];
  let combinedHashInput = "";

  for (const file of selectedFiles) {
    const content = file.content.slice(0, MAX_FILE_BYTES);
    combinedHashInput += `${file.path}:${hash(content)};`;
    findings.push(
      ...scanDocument({
        content,
        sourceName: payload.source_name || "uploaded-project",
        filePath: file.path,
        metadata: { ...(payload.metadata || {}), public_accessible: isPublicAddress(file.path) }
      })
    );
  }

  return aggregateScan({
    sourceName: payload.source_name || "uploaded-project",
    contentHash: hash(combinedHashInput),
    findings,
    mode: "project-folder",
    metadata: { scanned_files: selectedFiles.length }
  });
}

function absoluteUrl(baseUrl, raw) {
  try {
    return new URL(raw, baseUrl).toString();
  } catch {
    return null;
  }
}

function extractAssetUrls(html, baseUrl) {
  const urls = new Set([baseUrl]);
  const patterns = [
    /<script[^>]+src=["']([^"']+)["']/gi,
    /<link[^>]+href=["']([^"']+)["']/gi,
    /sourceMappingURL=([^\s*]+)/gi
  ];
  for (const pattern of patterns) {
    for (const match of html.matchAll(pattern)) {
      const resolved = absoluteUrl(baseUrl, match[1]);
      if (resolved && urls.size < MAX_WEBSITE_ASSETS) urls.add(resolved);
    }
  }
  for (const extra of ["/robots.txt", "/sitemap.xml", "/manifest.json", "/.env", "/config.js"]) {
    const resolved = absoluteUrl(baseUrl, extra);
    if (resolved && urls.size < MAX_WEBSITE_ASSETS) urls.add(resolved);
  }
  return [...urls];
}

async function fetchText(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "LeakShield-Pro-Security-Scanner/1.0" }
    });
    const contentType = response.headers.get("content-type") || "";
    if (!response.ok || (!contentType.includes("text") && !contentType.includes("json") && !contentType.includes("javascript") && !contentType.includes("xml"))) {
      return null;
    }
    return (await response.text()).slice(0, MAX_FILE_BYTES);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function scanWebsite(payload) {
  const target = payload.website_url || payload.url;
  let url;
  try {
    url = new URL(target.startsWith("http") ? target : `https://${target}`).toString();
  } catch {
    const error = new Error("A valid website URL is required.");
    error.statusCode = 400;
    throw error;
  }

  const mainHtml = await fetchText(url);
  if (!mainHtml) {
    const error = new Error("Website could not be fetched or did not return public text content.");
    error.statusCode = 422;
    throw error;
  }

  const urls = extractAssetUrls(mainHtml, url);
  const findings = [];
  let combinedHashInput = "";

  for (const address of urls) {
    const content = address === url ? mainHtml : await fetchText(address);
    if (!content) continue;
    combinedHashInput += `${address}:${hash(content)};`;
    findings.push(
      ...scanDocument({
        content,
        sourceName: url,
        sourceAddress: address,
        metadata: { ...(payload.metadata || {}), website: true, public_accessible: true }
      })
    );
  }

  return aggregateScan({
    sourceName: url,
    contentHash: hash(combinedHashInput),
    findings,
    mode: "website",
    metadata: { scanned_files: urls.length, scanned_addresses: urls }
  });
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method === "GET") return res.status(200).json([]);
  if (req.method !== "POST") return res.status(405).json({ detail: "Method not allowed" });

  try {
    const payload = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
    const mode = payload.mode || (payload.website_url || payload.url ? "website" : Array.isArray(payload.files) ? "project-folder" : "text");
    if (mode === "website") return res.status(201).json(await scanWebsite(payload));
    if (mode === "project-folder") return res.status(201).json(scanProject(payload));
    if (!payload.content) return res.status(400).json({ detail: "content is required" });
    return res.status(201).json(scanText(payload));
  } catch (error) {
    return res.status(error.statusCode || 500).json({ detail: error.message || "Scan failed" });
  }
};
