const MAX_AUDIT_RECORDS = 500;

function records() {
  if (!globalThis.__LEAKSHIELD_AUDIT_RECORDS__) {
    globalThis.__LEAKSHIELD_AUDIT_RECORDS__ = [];
  }
  return globalThis.__LEAKSHIELD_AUDIT_RECORDS__;
}

function addAuditRecord(record) {
  const list = records();
  list.unshift(record);
  if (list.length > MAX_AUDIT_RECORDS) list.length = MAX_AUDIT_RECORDS;
}

function listAuditRecords() {
  return records();
}

function clearAuditRecords() {
  records().length = 0;
}

module.exports = {
  addAuditRecord,
  clearAuditRecords,
  listAuditRecords
};
