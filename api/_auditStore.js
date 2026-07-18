const crypto = require("crypto");

const MAX_AUDIT_RECORDS = 500;
const AUDIT_PREFIX = "audit-users";

let blobClient;

function memoryRecords() {
  return (globalThis.__LEAKSHIELD_AUDIT_RECORDS__ ||= []);
}

function blob() {
  if (!process.env.BLOB_READ_WRITE_TOKEN && !(process.env.VERCEL_OIDC_TOKEN && process.env.BLOB_STORE_ID)) {
    return null;
  }
  if (blobClient !== undefined) return blobClient;
  try {
    blobClient = require("@vercel/blob");
  } catch {
    blobClient = null;
  }
  return blobClient;
}

function userIdFor(record) {
  const seed = record.session_id || record.id || "unknown";
  return `usr_${crypto.createHash("sha256").update(seed).digest("hex").slice(0, 18)}`;
}

function safeTimestamp(value) {
  const date = new Date(value || Date.now());
  return (Number.isNaN(date.getTime()) ? new Date() : date).toISOString().replace(/[:.]/g, "-");
}

function normalizeRecord(record) {
  const user_id = record.user_id || userIdFor(record);
  return {
    ...record,
    user_id,
    storage_scope: "redacted_user_box",
    storage_path:
      record.storage_path ||
      `${AUDIT_PREFIX}/${user_id}/records/${safeTimestamp(record.created_at)}_${record.id}.json`
  };
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
  return output + decoder.decode();
}

async function addAuditRecord(record) {
  const normalized = normalizeRecord(record);
  const client = blob();
  if (client) {
    try {
      await client.put(normalized.storage_path, JSON.stringify(normalized), {
        access: "private",
        allowOverwrite: true,
        contentType: "application/json",
        cacheControlMaxAge: 60
      });
    } catch {
      // Keep the scan successful and retain the record in this function instance.
    }
  }

  const records = memoryRecords();
  records.unshift(normalized);
  if (records.length > MAX_AUDIT_RECORDS) records.length = MAX_AUDIT_RECORDS;
  return normalized;
}

async function blobRecords() {
  const client = blob();
  if (!client) return [];
  const found = [];
  let cursor;
  do {
    const page = await client.list({ prefix: `${AUDIT_PREFIX}/`, limit: 100, cursor });
    found.push(...page.blobs.filter((item) => item.pathname.endsWith(".json")));
    cursor = page.cursor;
  } while (cursor && found.length < MAX_AUDIT_RECORDS);

  const loaded = await Promise.all(
    found.slice(0, MAX_AUDIT_RECORDS).map(async (item) => {
      try {
        const result = await client.get(item.pathname, { access: "private", useCache: false });
        return result?.stream ? JSON.parse(await streamToText(result.stream)) : null;
      } catch {
        return null;
      }
    })
  );
  return loaded.filter(Boolean);
}

function groupUsers(records) {
  const users = new Map();
  for (const record of records) {
    const normalized = normalizeRecord(record);
    const user = users.get(normalized.user_id) || {
      id: normalized.user_id,
      session_id: normalized.session_id,
      first_seen_at: normalized.created_at,
      latest_seen_at: normalized.created_at,
      scan_count: 0,
      finding_count: 0,
      critical_count: 0,
      latest_risk: "LOW",
      records: []
    };
    user.records.push(normalized);
    user.scan_count += 1;
    user.finding_count += normalized.result_shown_to_user?.finding_count || 0;
    if (normalized.result_shown_to_user?.overall_level === "CRITICAL") user.critical_count += 1;
    if (new Date(normalized.created_at) < new Date(user.first_seen_at)) user.first_seen_at = normalized.created_at;
    if (new Date(normalized.created_at) >= new Date(user.latest_seen_at)) {
      user.latest_seen_at = normalized.created_at;
      user.latest_risk = normalized.result_shown_to_user?.overall_level || user.latest_risk;
    }
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
  let records = memoryRecords();
  if (blob()) {
    try {
      const persisted = await blobRecords();
      records = [...persisted, ...memoryRecords()].filter(
        (record, index, all) => all.findIndex((candidate) => candidate.id === record.id) === index
      );
    } catch {
      // A temporary storage outage falls back to the current function instance.
    }
  }
  return records
    .map(normalizeRecord)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, MAX_AUDIT_RECORDS);
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
  memoryRecords().length = 0;
}

function storageProvider() {
  return blob() ? "vercel_blob_private" : "memory_fallback";
}

module.exports = { addAuditRecord, clearAuditRecords, listAuditRecords, listAuditUsers, storageProvider };
