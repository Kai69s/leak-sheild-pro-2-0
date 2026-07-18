const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

process.env.ADMIN_EMAIL = "admin@example.test";
process.env.ADMIN_PASSWORD = "test-password";
process.env.ADMIN_SESSION_SECRET = "test-session-secret-with-enough-entropy";

const adminHandler = require("../api/admin");
const { clearAuditRecords, listAuditRecords } = require("../api/_auditStore");
const scanHandler = require("../api/scans");

function invoke(handler, { method = "GET", body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const output = { headers: {} };
    const req = { method, body, headers };
    const res = {
      setHeader(name, value) {
        output.headers[name] = value;
        return this;
      },
      status(statusCode) {
        output.status = statusCode;
        return this;
      },
      json(responseBody) {
        output.body = responseBody;
        resolve(output);
        return this;
      },
      end() {
        resolve(output);
        return this;
      }
    };
    Promise.resolve(handler(req, res)).catch(reject);
  });
}

test.beforeEach(async () => {
  await clearAuditRecords();
  globalThis.__LEAKSHIELD_RATE_LIMITS__?.clear();
});

test("scans the supplied leak sample and stores only a redacted audit summary", async () => {
  const content = fs.readFileSync(path.join(__dirname, "../samples/sample_leak.txt"), "utf8");
  const response = await invoke(scanHandler, {
    method: "POST",
    body: {
      mode: "text",
      content,
      source_name: "sample_leak.txt",
      metadata: { client_session_id: "test-session" }
    }
  });

  assert.equal(response.status, 201);
  assert.equal(response.body.overall_level, "CRITICAL");
  assert.ok(response.body.finding_count > 0);

  const records = await listAuditRecords();
  assert.equal(records.length, 1);
  assert.equal(records[0].submitted_input.source_name, "sample_leak.txt");
  assert.equal(JSON.stringify(records).includes(content.trim()), false);
  assert.equal(records[0].request_context.network_data, "not_collected");
});

test("rejects unsupported scan modes", async () => {
  const response = await invoke(scanHandler, {
    method: "POST",
    body: { mode: "unsupported", content: "hello" }
  });
  assert.equal(response.status, 400);
  assert.match(response.body.detail, /mode must be/);
});

test("rejects an empty project scan", async () => {
  const response = await invoke(scanHandler, {
    method: "POST",
    body: { mode: "project-folder", files: [] }
  });
  assert.equal(response.status, 400);
  assert.match(response.body.detail, /project file/);
});

test("admin login can read redacted audit records", async () => {
  await invoke(scanHandler, {
    method: "POST",
    body: {
      content: "api_key='prod_live_ci_token_9f2b7c4a6d8e1f0a2b3c4d5e'",
      source_name: "deployment.env",
      metadata: { client_session_id: "admin-test-session" }
    }
  });
  const login = await invoke(adminHandler, {
    method: "POST",
    body: { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD }
  });
  assert.equal(login.status, 200);
  assert.ok(login.body.token);

  const audit = await invoke(adminHandler, {
    headers: { authorization: `Bearer ${login.body.token}` }
  });
  assert.equal(audit.status, 200);
  assert.equal(audit.body.records.length, 1);
  assert.equal(audit.body.users.length, 1);
});
