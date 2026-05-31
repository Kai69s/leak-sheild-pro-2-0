const crypto = require("crypto");

const MAX_AUDIT_RECORDS = 500;
const AUDIT_PREFIX = "audit-users";

let blobClient = null;

function records() {
  if (!globalThis.__LEAKSHIELD_AUDIT_RECORDS__) {
    globalThis.__LEAKSHIELD_AUDIT_RECORDS__ = [];
  }
  return globalThis.__LEAKSHIELD_AUDIT_RECORDS__;
}

function blobEnabled() {
  return Boolean(process.env.BLOB_READ_WRITE_TOKEN || (process.env.VERCEL_OIDC_TOKEN && process.env.BLOB_STORE_ID));
}

function blob() {
  if (!blobEnabled()) return null;
  if (!blobClient) {
    try {
      blobClient = require("@vercel/blob");
    } catch {
      blobClient = null;
    }
  }
  return blobClient;
}

function userIdFor(record) {
  const seed = record.session_id || record.request_context?.ip_address || record.id || "unknown";
  return `usr_${crypto.createHash("sha256").update(seed).digest("hex").slice(0, 18)}`;
}

function safeTimestamp(value) {
  return new Date(value || Date.now()).toISOString().replace(/[:.]/g, "-");
}

function recordPath(record) {
  return `${AUDIT_PREFIX}/${record.user_id}/records/${safeTimestamp(record.created_at)}_${record.id}.json`;
}

async function streamToText(stream) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let output = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    output += decoder.decode(value, { stream: true });
  }
  output += decoder.decode();
  return output;
}

function normalizeRecord(record) {
  const user_id = record.user_id || userIdFor(record);
  return {
    ...record,
    user_id,
    storage_scope: "user_box",
    storage_path: record.storage_path || recordPath({ ...record, user_id })
  };
}

async function addAuditRecord(record) {
  const normalized = normalizeRecord(record);
  if (blob()) {
    await blob().put(normalized.storage_path, JSON.stringify(normalized, null, 2), {
      access: "private",
      allowOverwrite: true,
      contentType: "application/json",
      cacheControlMaxAge: 60
    });
  }

  const list = records();
  list.unshift(normalized);
  if (list.length > MAX_AUDIT_RECORDS) list.length = MAX_AUDIT_RECORDS;
  return normalized;
}

async function blobRecords() {
  const client = blob();
  if (!client) return [];
  const found = [];
  let cursor;
  do {
    const page = await client.list({
      prefix: `${AUDIT_PREFIX}/`,
      limit: 100,
      cursor
    });
    found.push(...page.blobs.filter((item) => item.pathname.endsWith(".json")));
    cursor = page.cursor;
  } while (cursor && found.length < MAX_AUDIT_RECORDS);

  const loaded = await Promise.all(
    found.slice(0, MAX_AUDIT_RECORDS).map(async (item) => {
      try {
        const result = await client.get(item.pathname, { access: "private", useCache: false });
        if (!result?.stream) return null;
        return JSON.parse(await streamToText(result.stream));
      } catch {
        return null;
      }
    })
  );
  return loaded.filter(Boolean);
}

function groupUsers(list) {
  const users = new Map();
  for (const record of list) {
    const normalized = normalizeRecord(record);
    const user = users.get(normalized.user_id) || {
      id: normalized.user_id,
      session_id: normalized.session_id,
      first_seen_at: normalized.created_at,
      latest_seen_at: normalized.created_at,
      scan_count: 0,
      finding_count: 0,
      critical_count: 0,
      latest_ip: "unknown",
      latest_risk: "LOW",
      records: []
    };
    user.records.push(normalized);
    user.scan_count += 1;
    user.finding_count += normalized.result_shown_to_user?.finding_count || 0;
    if (normalized.result_shown_to_user?.overall_level === "CRITICAL") user.critical_count += 1;
    const seenAt = [user.latest_seen_at, normalized.created_at].sort();
    user.first_seen_at = seenAt[0];
    user.latest_seen_at = seenAt[seenAt.length - 1];
    user.latest_ip = normalized.request_context?.ip_address || user.latest_ip;
    user.latest_risk = normalized.result_shown_to_user?.overall_level || user.latest_risk;
    users.set(normalized.user_id, user);
  }

  return [...users.values()]
    .map((user) => ({
      ...user,
      records: user.records.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    }))
    .sort((a, b) => new Date(b.latest_seen_at) - new Date(a.latest_seen_at));
}

async function listAuditRecords() {
  const loaded = blob() ? await blobRecords() : records();
  return loaded.map(normalizeRecord).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, MAX_AUDIT_RECORDS);
}

async function listAuditUsers() {
  return groupUsers(await listAuditRecords());
}

async function clearAuditRecords() {
  const client = blob();
  if (client) {
    const paths = [];
    let cursor;
    do {
      const page = await client.list({ prefix: `${AUDIT_PREFIX}/`, limit: 100, cursor });
      paths.push(...page.blobs.map((item) => item.pathname));
      cursor = page.cursor;
    } while (cursor);
    if (paths.length) await client.del(paths);
  }
  records().length = 0;
}

module.exports = {
  addAuditRecord,
  clearAuditRecords,
  listAuditRecords,
  listAuditUsers
};
