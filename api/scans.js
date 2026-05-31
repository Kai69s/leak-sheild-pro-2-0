const crypto = require("crypto");
const { addAuditRecord } = require("./_auditStore");

const MAX_FOLDER_FILES = 140;
const MAX_FILE_BYTES = 220_000;
const MAX_WEBSITE_ASSETS = 36;
const FETCH_TIMEOUT_MS = 6500;
const MAX_CONCURRENCY = 6;

const severityBase = { LOW: 20, MEDIUM: 45, HIGH: 70, CRITICAL: 88 };

const highRiskContext = ["production", "prod", "live", "public repo", "github", "exposed", "main branch", "website", "public", "client"];
const lowRiskContext = ["test", "dev", "development", "staging", "sandbox", "local", "mock"];
const ignoredFolderParts = ["node_modules", ".git", "dist", "build", ".next", "coverage", "__pycache__", ".venv", "vendor"];
const publicRiskPaths = [".env", ".pem", ".key", "id_rsa", "config", "settings", "firebase", "aws", "credential", "secret", "public", "static"];
const exampleMarkers = ["example", "sample", "dummy", "changeme", "placeholder", "xxxxx", "test_test", "your_", "<", ">"];

const commonPublicPaths = [
  "/robots.txt",
  "/sitemap.xml",
  "/manifest.json",
  "/asset-manifest.json",
  "/.env",
  "/.env.local",
  "/.env.production",
  "/config.js",
  "/config.json",
  "/env.js",
  "/runtime-config.js",
  "/firebase-messaging-sw.js",
  "/.well-known/security.txt",
  "/server-status",
  "/debug",
  "/api/config",
  "/api/env",
  "/api/settings",
  "/_next/static/chunks/webpack.js"
];

function headerValue(req, name) {
  const value = req.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value || "";
}

function clientIp(req) {
  return (
    headerValue(req, "x-forwarded-for").split(",")[0].trim() ||
    headerValue(req, "x-real-ip") ||
    headerValue(req, "x-vercel-forwarded-for") ||
    "unknown"
  );
}

function requestContext(req) {
  return {
    ip_address: clientIp(req),
    user_agent: headerValue(req, "user-agent"),
    country: headerValue(req, "x-vercel-ip-country") || "unknown",
    region: headerValue(req, "x-vercel-ip-country-region") || "unknown",
    city: headerValue(req, "x-vercel-ip-city") || "unknown",
    timezone: headerValue(req, "x-vercel-ip-timezone") || "unknown",
    mac_address: "not_available_in_browser",
    mac_address_note: "Standard web browsers do not expose client MAC addresses to websites.",
    vpn_status: "unknown",
    vpn_blocked: false
  };
}

function submittedInput(payload, mode) {
  if (mode === "website") {
    return {
      mode,
      website_url: payload.website_url || payload.url || "",
      source_name: payload.source_name || payload.website_url || payload.url || "website-scan"
    };
  }
  if (mode === "project-folder") {
    return {
      mode,
      source_name: payload.source_name || "uploaded-project",
      files: Array.isArray(payload.files)
        ? payload.files.map((file) => ({
            path: file.path,
            size: file.size,
            content: typeof file.content === "string" ? file.content.slice(0, MAX_FILE_BYTES) : ""
          }))
        : []
    };
  }
  return {
    mode,
    source_name: payload.source_name || "manual-input",
    content: payload.content || ""
  };
}

async function auditScan(req, payload, mode, result) {
  const metadata = payload.metadata || {};
  await addAuditRecord({
    id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    session_id: metadata.client_session_id || "unknown",
    consent: metadata.consent || {},
    request_context: requestContext(req),
    submitted_input: submittedInput(payload, mode),
    result_shown_to_user: result
  });
}

const rules = [
  rule("aws-access-key-id", "AWS Access Key ID", "HIGH", 0.95, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, {
    description: "An AWS access key identifier was exposed.",
    impact: "Attackers can pair it with a secret key to access AWS APIs.",
    consequence: "Cloud resources, S3 data, IAM permissions, and billing can be abused.",
    remediation: "Disable the access key, rotate credentials, and audit CloudTrail activity."
  }),
  rule("aws-secret-access-key", "AWS Secret Access Key", "CRITICAL", 0.9, /\baws(?:_|-)?(?:secret|private)?(?:_|-)?access(?:_|-)?key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})/gi, {
    description: "An AWS secret access key value was exposed.",
    impact: "Attackers may authenticate directly to AWS services.",
    consequence: "This can lead to infrastructure takeover, data theft, and financial loss.",
    remediation: "Revoke the key immediately, rotate dependent secrets, and review IAM permissions."
  }),
  rule("github-token", "GitHub Token", "CRITICAL", 0.94, /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g, {
    description: "A GitHub access token was exposed.",
    impact: "Attackers can access repositories, workflows, packages, or organization resources depending on token scope.",
    consequence: "Source code theft, CI/CD compromise, and supply-chain injection may occur.",
    remediation: "Revoke the token in GitHub, rotate any dependent credentials, and review audit logs."
  }),
  rule("openai-api-key", "OpenAI API Key", "HIGH", 0.92, /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,180}\b/g, {
    description: "An OpenAI API key-like token was exposed.",
    impact: "Attackers can spend quota, access model endpoints, or abuse the associated account.",
    consequence: "Unexpected billing and data exposure through API usage may occur.",
    remediation: "Revoke the key, create a new scoped key, and keep it server-side only."
  }),
  rule("google-api-key", "Google API Key", "MEDIUM", 0.82, /\bAIza[0-9A-Za-z_-]{35}\b/g, {
    description: "A Google API key was exposed in public content.",
    impact: "Attackers can abuse enabled Google APIs if restrictions are missing.",
    consequence: "Quota exhaustion, billing abuse, and unauthorized API calls may occur.",
    remediation: "Restrict the key by HTTP referrer/IP/API, rotate it if unrestricted, and move sensitive services server-side."
  }),
  rule("stripe-secret-key", "Stripe Secret Key", "CRITICAL", 0.96, /\b(?:sk_live|rk_live)_[A-Za-z0-9]{24,120}\b/g, {
    description: "A live Stripe secret or restricted key was exposed.",
    impact: "Attackers can access payment operations permitted by the key.",
    consequence: "Payment data, refunds, charges, and customer records may be compromised.",
    remediation: "Revoke the key in Stripe, rotate webhooks if needed, and investigate dashboard logs."
  }),
  rule("slack-token", "Slack Token", "HIGH", 0.9, /\bxox[baprs]-[A-Za-z0-9-]{20,220}\b/g, {
    description: "A Slack token was exposed.",
    impact: "Attackers can call Slack APIs with the leaked workspace identity.",
    consequence: "Messages, workspace data, and integrations may be abused.",
    remediation: "Revoke the token, rotate app credentials, and review Slack audit logs."
  }),
  rule("sendgrid-key", "SendGrid API Key", "HIGH", 0.88, /\bSG\.[A-Za-z0-9_-]{16,40}\.[A-Za-z0-9_-]{16,80}\b/g, {
    description: "A SendGrid API key was exposed.",
    impact: "Attackers can send email through the associated account.",
    consequence: "Spam, phishing, domain reputation damage, and billing abuse may occur.",
    remediation: "Revoke the key, rotate email credentials, and review recent mail activity."
  }),
  rule("generic-api-key", "API Key", "MEDIUM", 0.72, /\b(api[_-]?key|apikey|x-api-key|client_secret|secret_key|access_token|auth_token)\b\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{20,180})/gi, {
    description: "A secret-like API credential assignment was found.",
    impact: "Attackers can call the associated service as the leaked identity.",
    consequence: "Quota abuse, data access, account takeover, or service disruption may occur.",
    remediation: "Rotate the value, revoke exposed tokens, and move runtime secrets to a managed secret store."
  }),
  rule("password-assignment", "Password", "HIGH", 0.7, /\b(password|passwd|pwd|db_password)\b\s*[:=]\s*["']([^"'\s]{8,128})["']?/gi, {
    description: "A hardcoded password-like assignment was detected.",
    impact: "Attackers can authenticate to the protected account or system.",
    consequence: "Credential reuse may expand the breach to databases, apps, or admin panels.",
    remediation: "Change the password, invalidate sessions, remove it from public files and Git history, and load it from environment variables."
  }),
  rule("database-url", "Database URL", "CRITICAL", 0.9, /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"']+:[^\s"']+@[^\s"']+/gi, {
    description: "A database or broker connection string containing credentials was exposed.",
    impact: "Attackers can connect to the service if network access is available.",
    consequence: "Sensitive records, queues, cache contents, or infrastructure data may be compromised.",
    remediation: "Rotate credentials, restrict network access, remove the URL from public files, and review service logs."
  }),
  rule("basic-auth-url", "Basic Auth URL", "HIGH", 0.82, /\bhttps?:\/\/[^\/\s"':]+:[^\/\s"']+@[^\s"']+/gi, {
    description: "A URL containing embedded username and password was exposed.",
    impact: "Attackers can reuse the embedded credentials against the target service.",
    consequence: "Protected endpoints, dashboards, or upstream services may be accessed.",
    remediation: "Rotate the embedded credentials and remove authentication material from public URLs."
  }),
  rule("bearer-token", "Bearer Token", "HIGH", 0.8, /\bbearer\s+([A-Za-z0-9._-]{24,2048})/gi, {
    description: "A bearer token was exposed.",
    impact: "Attackers can replay the token until it expires or is revoked.",
    consequence: "API sessions, user data, and privileged workflows may be compromised.",
    remediation: "Revoke the token, shorten token lifetime, rotate signing keys if needed, and prevent token rendering in public responses."
  }),
  rule("jwt-token", "JWT Token", "HIGH", 0.86, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, {
    description: "A JSON Web Token was found.",
    impact: "Attackers can impersonate the token subject if the token is valid.",
    consequence: "Application sessions and API authorizations may be abused.",
    remediation: "Revoke the JWT, rotate affected signing secrets, and ensure tokens are never exposed in HTML, JavaScript bundles, or logs."
  }),
  rule("private-key-block", "Private Key", "CRITICAL", 0.98, /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, {
    description: "A private cryptographic key block was exposed.",
    impact: "Attackers can decrypt traffic, sign payloads, or access servers depending on key use.",
    consequence: "SSH access, TLS trust, package signing, or encrypted data may be compromised.",
    remediation: "Replace the key pair, remove it from public access and Git history, rotate all dependent trust, and audit key usage."
  })
];

function rule(rule_id, secret_type, severity, confidence, pattern, text) {
  return {
    rule_id,
    secret_type,
    severity,
    confidence,
    pattern,
    description: text.description,
    attacker_impact: text.impact,
    consequence: text.consequence,
    remediation: text.remediation
  };
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function entropy(value) {
  const chars = [...value];
  const freq = chars.reduce((acc, char) => ((acc[char] = (acc[char] || 0) + 1), acc), {});
  return chars.reduce((sum, char) => {
    const p = freq[char] / chars.length;
    return sum - p * Math.log2(p);
  }, 0);
}

function isLikelySecret(value, ruleId) {
  const normalized = String(value || "").trim();
  if (!normalized || exampleMarkers.some((term) => normalized.toLowerCase().includes(term))) return false;
  if (["aws-access-key-id", "google-api-key", "jwt-token", "private-key-block", "database-url", "basic-auth-url"].includes(ruleId)) return true;
  if (normalized.length < 20) return false;
  if (/^(true|false|null|undefined|localhost|127\.0\.0\.1)$/i.test(normalized)) return false;
  if (/^[a-z-]+$/i.test(normalized) && normalized.length < 28) return false;
  return entropy(normalized) >= 3.15 || /[0-9]/.test(normalized) || /[._~+/=-]/.test(normalized);
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
  return normalized.startsWith("http://") || normalized.startsWith("https://") || publicRiskPaths.some((part) => normalized.includes(part));
}

function shouldSkipFolderPath(path = "") {
  const normalized = path.toLowerCase().replaceAll("\\", "/");
  return ignoredFolderParts.some((part) => normalized.split("/").includes(part));
}

function scoreFinding(rule, value, content, contextSnippet, metadata, address) {
  let score = severityBase[rule.severity] * rule.confidence;
  const context = `${content.slice(Math.max(0, content.indexOf(value) - 220), content.indexOf(value) + 220)} ${contextSnippet} ${JSON.stringify(metadata || {})} ${address || ""}`.toLowerCase();
  const adjustments = [];

  if (highRiskContext.some((term) => context.includes(term))) {
    score += 15;
    adjustments.push("High-risk deployment or public exposure context detected.");
  }
  if (lowRiskContext.some((term) => context.includes(term))) {
    score -= 8;
    adjustments.push("Non-production context reduced the final risk.");
  }
  if (["Private Key", "Database URL", "AWS Secret Access Key", "Stripe Secret Key"].includes(rule.secret_type)) {
    score += 9;
    adjustments.push("Secret type has direct authentication or financial impact.");
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
  const addresses = [...new Set(findings.map((item) => item.file_path || item.source_address || item.source_name).filter(Boolean))].slice(0, 10);
  const types = [...new Set(findings.map((item) => item.secret_type))].slice(0, 6).join(", ");
  const actionIntro =
    mode === "website"
      ? "Remove exposed secrets from the public website response, JavaScript bundles, source maps, and public config endpoints."
      : "Remove exposed secrets from the listed project files before publishing, deploying, or committing.";

  return {
    priority,
    summary: `${findings.length} exposure(s) detected across ${addresses.length} address(es). Highest priority: ${priority}. Secret classes: ${types}.`,
    exposed_addresses: addresses,
    actions: [
      actionIntro,
      "Immediately revoke and rotate every exposed credential, token, password, key, or database URL.",
      "Move all runtime secrets into server-only environment variables, a vault, or a cloud secret manager.",
      "Purge the secret from Git history, source maps, static builds, caches, and deployment artifacts, then redeploy clean builds.",
      "Add automated secret scanning to CI/CD and block releases when public bundles contain secret-like values.",
      "Review access logs for the affected providers from the first public exposure timestamp."
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
      if (!isLikelySecret(value, rule.rule_id)) continue;
      const offset = match.index || 0;
      const key = `${rule.rule_id}:${hash(value)}:${filePath || sourceAddress || sourceName}:${offset}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const pos = lineColumn(content, offset);
      const address = filePath || sourceAddress || sourceName;
      const contextSnippet = content.slice(Math.max(0, offset - 110), Math.min(content.length, offset + match[0].length + 110)).replace(/\n/g, "\\n");
      const risk = scoreFinding(rule, value, content, contextSnippet, metadata, address);
      const adjustmentText = risk.adjustments.join(" ") || "No contextual adjustment was applied.";
      findings.push({
        id: crypto.randomUUID(),
        rule_id: rule.rule_id,
        secret_type: rule.secret_type,
        severity: rule.severity,
        confidence: rule.confidence,
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

function dedupeFindings(findings) {
  const best = new Map();
  for (const item of findings) {
    const key = `${item.rule_id}:${item.value_hash}:${item.file_path || item.source_address || item.source_name}:${item.line_number}:${item.column_start}`;
    const existing = best.get(key);
    if (!existing || item.risk_score > existing.risk_score) best.set(key, item);
  }
  return [...best.values()];
}

function aggregateScan({ sourceName, contentHash, findings, mode, metadata }) {
  const cleanFindings = dedupeFindings(findings).sort(
    (a, b) => (a.file_path || a.source_address || "").localeCompare(b.file_path || b.source_address || "") || a.line_number - b.line_number
  );
  const highest = cleanFindings.length ? Math.max(...cleanFindings.map((item) => item.risk_score)) : 0;
  const overallScore = cleanFindings.length ? Math.min(100, Number((highest + Math.min(12, (cleanFindings.length - 1) * 2.5)).toFixed(2))) : 0;
  return {
    id: crypto.randomUUID(),
    mode,
    source_name: sourceName,
    content_hash: contentHash,
    overall_score: overallScore,
    overall_level: levelForScore(overallScore),
    finding_count: cleanFindings.length,
    public_exposure_count: cleanFindings.filter((item) => item.public_accessible).length,
    scanned_files: metadata.scanned_files || 1,
    scanned_addresses: metadata.scanned_addresses || [],
    skipped_addresses: metadata.skipped_addresses || [],
    recommendation: recommendationFor(cleanFindings, mode),
    cache_hit: false,
    created_at: new Date().toISOString(),
    findings: cleanFindings
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
    if (!raw || raw.startsWith("data:") || raw.startsWith("mailto:") || raw.startsWith("tel:") || raw.startsWith("#")) return null;
    return new URL(raw.replace(/&amp;/g, "&"), baseUrl).toString();
  } catch {
    return null;
  }
}

function sameOrigin(url, origin) {
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

function addUrl(urls, baseUrl, raw) {
  const resolved = absoluteUrl(baseUrl, raw);
  if (!resolved) return;
  const parsed = new URL(resolved);
  const origin = new URL(baseUrl).origin;
  if (parsed.origin !== origin) return;
  if (!["http:", "https:"].includes(parsed.protocol)) return;
  if (urls.size < MAX_WEBSITE_ASSETS) urls.add(parsed.toString());
}

function extractAssetUrls(html, baseUrl) {
  const urls = new Set([baseUrl]);
  const patterns = [
    /<script[^>]+src=["']([^"']+)["']/gi,
    /<link[^>]+href=["']([^"']+)["']/gi,
    /<a[^>]+href=["']([^"']+\.(?:js|json|map|txt|xml|env|config))["']/gi,
    /(?:src|href|url)\(["']?([^"')\s]+)["']?\)/gi,
    /(?:import|from)\s*["']([^"']+)["']/gi,
    /sourceMappingURL=([^\s*]+)/gi,
    /["']([^"']+\.(?:js|mjs|json|map|txt|xml|env|config))["']/gi
  ];
  for (const pattern of patterns) {
    for (const match of html.matchAll(pattern)) {
      addUrl(urls, baseUrl, match[1]);
    }
  }
  for (const extra of commonPublicPaths) addUrl(urls, baseUrl, extra);
  return [...urls];
}

function isTextualResponse(url, contentType) {
  const lowered = (contentType || "").toLowerCase();
  const extension = new URL(url).pathname.toLowerCase();
  return (
    lowered.includes("text") ||
    lowered.includes("json") ||
    lowered.includes("javascript") ||
    lowered.includes("ecmascript") ||
    lowered.includes("xml") ||
    lowered.includes("html") ||
    [".js", ".mjs", ".json", ".map", ".txt", ".xml", ".env", ".config"].some((ext) => extension.endsWith(ext))
  );
}

async function fetchText(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": "LeakShield-Pro-Public-Exposure-Scanner/2.0",
        accept: "text/html,application/javascript,application/json,text/plain,application/xml;q=0.9,*/*;q=0.2"
      }
    });
    const contentType = response.headers.get("content-type") || "";
    if (!response.ok || !isTextualResponse(response.url || url, contentType)) {
      return { url, ok: false, status: response.status, content: "" };
    }
    return { url: response.url || url, ok: true, status: response.status, content: (await response.text()).slice(0, MAX_FILE_BYTES) };
  } catch (error) {
    return { url, ok: false, status: 0, content: "", error: error.name || "fetch-failed" };
  } finally {
    clearTimeout(timer);
  }
}

async function mapLimit(items, limit, worker) {
  const results = [];
  let index = 0;
  async function next() {
    const current = index++;
    if (current >= items.length) return;
    results[current] = await worker(items[current]);
    await next();
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, next));
  return results;
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

  const main = await fetchText(url);
  if (!main.ok || !main.content) {
    const error = new Error("Website could not be fetched or did not return public text content.");
    error.statusCode = 422;
    throw error;
  }

  const discovered = extractAssetUrls(main.content, main.url);
  const secondPassSeeds = discovered.filter((asset) => sameOrigin(asset, new URL(main.url).origin) && asset !== main.url).slice(0, 10);
  const seedResults = await mapLimit(secondPassSeeds, MAX_CONCURRENCY, fetchText);
  for (const item of seedResults) {
    if (item?.ok && item.content) extractAssetUrls(item.content, item.url).forEach((asset) => addUrl(new Set(discovered), main.url, asset));
  }
  const urls = [...new Set([...discovered, ...seedResults.filter((item) => item?.ok).flatMap((item) => extractAssetUrls(item.content, item.url))])].slice(0, MAX_WEBSITE_ASSETS);
  const fetched = await mapLimit(urls, MAX_CONCURRENCY, async (address) => (address === main.url ? main : fetchText(address)));
  const findings = [];
  const skipped = [];
  let combinedHashInput = "";

  for (const item of fetched) {
    if (!item?.ok || !item.content) {
      if (item?.url) skipped.push(item.url);
      continue;
    }
    combinedHashInput += `${item.url}:${hash(item.content)};`;
    findings.push(
      ...scanDocument({
        content: item.content,
        sourceName: main.url,
        sourceAddress: item.url,
        metadata: { ...(payload.metadata || {}), website: true, public_accessible: true }
      })
    );
  }

  return aggregateScan({
    sourceName: main.url,
    contentHash: hash(combinedHashInput),
    findings,
    mode: "website",
    metadata: { scanned_files: fetched.filter((item) => item?.ok).length, scanned_addresses: urls, skipped_addresses: skipped.slice(0, 12) }
  });
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), payment=(), usb=()");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method === "GET") return res.status(200).json([]);
  if (req.method !== "POST") return res.status(405).json({ detail: "Method not allowed" });

  try {
    const payload = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
    const mode = payload.mode || (payload.website_url || payload.url ? "website" : Array.isArray(payload.files) ? "project-folder" : "text");
    if (mode === "website") {
      const result = await scanWebsite(payload);
      await auditScan(req, payload, mode, result);
      return res.status(201).json(result);
    }
    if (mode === "project-folder") {
      const result = scanProject(payload);
      await auditScan(req, payload, mode, result);
      return res.status(201).json(result);
    }
    if (!payload.content) return res.status(400).json({ detail: "content is required" });
    const result = scanText(payload);
    await auditScan(req, payload, mode, result);
    return res.status(201).json(result);
  } catch (error) {
    return res.status(error.statusCode || 500).json({ detail: error.message || "Scan failed" });
  }
};
