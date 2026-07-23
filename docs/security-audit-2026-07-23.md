# LeakShield Pro Security Audit

**Audit date:** 2026-07-23

**Scope:** Entire tracked repository, active FastAPI service, React client, backward-compatible Node serverless API, dependencies, Vercel configuration, Docker configuration, tests, and Git history

**Method:** Manual threat modeling and code review, OWASP Top 10:2025, OWASP ASVS 5.0, CWE Top 25:2025, SANS Top 25, Bandit, Ruff, pip-audit, npm audit, npm registry signature verification, detect-secrets, and regression testing

## Executive Summary

The audit found 12 security issues: 4 High, 5 Medium, and 3 Low. All 12 were fixed. No Critical issue and no known vulnerable dependency remain.

The score is an internal engineering score, not a certification:

| Measure | Before | After |
| --- | ---: | ---: |
| Security score | 52/100 | 92/100 |
| Confirmed issues | 12 | 0 open |
| Automated tests | 15 | 26 |
| Known dependency vulnerabilities | 0 | 0 |

## Findings And Fixes

### LSP-SEC-01: Cross-user scan access

- **Severity:** High
- **CWE:** CWE-639, CWE-862
- **OWASP:** A01:2025 Broken Access Control
- **Affected code:** `backend/app/api/routes.py:26`, `backend/app/api/routes.py:39`, `backend/app/api/routes.py:58`
- **Problem:** Scan list and detail endpoints did not associate scans with a browser session.
- **Attack scenario:** A user who obtained or guessed a scan identifier could request another user's security findings and scan history.
- **Fix:** Every scan now has a one-way hashed owner identifier derived from a canonical random browser UUID. Create, list, detail, comparison, and storage queries enforce that owner.
- **Verification:** `backend/tests/test_api_security.py` confirms session B cannot list or fetch session A's scan.

### LSP-SEC-02: Raw secrets returned in finding context

- **Severity:** High
- **CWE:** CWE-200, CWE-312
- **OWASP:** A04:2025 Cryptographic Failures
- **Affected code:** `backend/app/engines/detection/scanner.py:72`, `api/scans.js:389`
- **Problem:** The preview value was masked, but the surrounding context could still contain the complete password, token, key, or a nearby second secret.
- **Attack scenario:** Anyone with access to a scan response, browser storage, logs, or the administrator audit view could recover a supposedly redacted credential.
- **Fix:** Every supported secret pattern is redacted from context before HTML encoding, response serialization, or audit storage. Detailed scan results now use session storage rather than persistent local storage.
- **Verification:** Python and Node regression tests assert the original credential is absent from the response and stored audit record.

### LSP-SEC-03: Cross-session cache data leak

- **Severity:** High
- **CWE:** CWE-200, CWE-639
- **OWASP:** A01:2025 Broken Access Control
- **Affected code:** `backend/app/services/scan_service.py:47`
- **Problem:** Identical input shared one cache key across all users.
- **Attack scenario:** A second user submitting the same content could receive the first user's scan identifier and cached result.
- **Fix:** Cache keys include the hashed owner identifier. Persisted scans and scan comparisons also enforce the same owner.

### LSP-SEC-04: Server-side request forgery and DNS rebinding

- **Severity:** High
- **CWE:** CWE-918
- **OWASP:** A01:2025 Broken Access Control, A10:2025 Mishandling of Exceptional Conditions
- **Affected code:** `backend/app/engines/assessment/website.py:80`, `backend/app/engines/assessment/website.py:103`, `backend/app/engines/assessment/website.py:123`, `api/scans.js:615`, `api/scans.js:653`
- **Problem:** Public-host validation and the actual connection could perform separate DNS resolutions. Subdomain requests also lacked complete private-address enforcement.
- **Attack scenario:** An attacker-controlled hostname could first resolve publicly, then change to a loopback, private, link-local, or cloud metadata address when the scanner connected.
- **Fix:** URLs reject credentials, non-HTTP schemes, local names, non-global addresses, and sensitive query strings. HTTP and TLS connections are pinned to the validated public IP while retaining the original Host header and TLS server name. Redirects and discovered subdomains are independently revalidated.
- **Verification:** Tests cover private targets, invalid ports, query removal, private subdomains, and IP pinning. A real HTTPS request to `example.com` succeeded through the pinned path.

### LSP-SEC-05: Administrator login brute force

- **Severity:** Medium
- **CWE:** CWE-307
- **OWASP:** A07:2025 Authentication Failures
- **Affected code:** `backend/app/security.py:116`, `backend/app/api/admin.py:205`, `api/admin.js:117`
- **Problem:** The active Python administrator login had no attempt limit.
- **Attack scenario:** An attacker could repeatedly guess the administrator password without delay.
- **Fix:** Login is limited to five attempts per 15 minutes. Buckets are bounded and only trust platform-supplied forwarding headers on Vercel. Configured administrator passwords must be at least 12 characters.

### LSP-SEC-06: Resource exhaustion

- **Severity:** Medium
- **CWE:** CWE-400, CWE-770
- **OWASP:** A06:2025 Insecure Design
- **Affected code:** `backend/app/security.py:12`, `backend/app/schemas.py:9`, `backend/app/services/scan_service.py:35`, `backend/app/engines/detection/scanner.py:9`, `frontend/src/App.jsx:51`, `api/scans.js:8`
- **Problem:** Request bodies, metadata, browser file reads, finding counts, rate-limit maps, and full website assessments were not consistently bounded.
- **Attack scenario:** Repeated large submissions or content containing thousands of matches could consume memory and CPU, especially in a free serverless function.
- **Fix:** Added a 2 MB transport limit, per-mode byte limits, metadata and file limits, finding caps, bounded rate-limit maps, an overall 45-second website deadline, streamed response limits, and an O(log n) line-position calculation.

### LSP-SEC-07: Sensitive URL data in logs and storage

- **Severity:** Medium
- **CWE:** CWE-532, CWE-598
- **OWASP:** A09:2025 Security Logging and Alerting Failures
- **Affected code:** `backend/app/engines/assessment/website.py:80`, `backend/app/main.py:26`, `api/scans.js:637`
- **Problem:** Website query strings could contain reset tokens, API keys, or signed URLs and were retained in errors, logs, and stored scan addresses.
- **Attack scenario:** A legitimate scan of a credential-bearing link could copy that credential into platform logs or scan history.
- **Fix:** User information, query strings, and fragments are removed before network use, logging, caching, or persistence. Routine HTTP client request logging is reduced to warnings without suppressing security warnings.

### LSP-SEC-08: Insecure infrastructure defaults

- **Severity:** Medium
- **CWE:** CWE-250, CWE-276, CWE-798
- **OWASP:** A02:2025 Security Misconfiguration
- **Affected code:** `docker-compose.yml:7`, `docker-compose.yml:10`, `backend/Dockerfile:17`, `frontend/Dockerfile:10`, `backend/.env.example:3`
- **Problem:** The repository contained a default database password, exposed database/cache ports on every interface, and ran application containers as root.
- **Attack scenario:** A developer launching the stack on a shared network could unintentionally expose predictable database credentials or increase container-breakout impact.
- **Fix:** Secrets are required from an ignored local environment file, service ports bind to loopback, SQLite is the safe zero-configuration default, both application containers run as unprivileged users, and Docker build contexts exclude secrets and local artifacts.

### LSP-SEC-09: Incomplete supply-chain controls

- **Severity:** Medium
- **CWE:** CWE-1104
- **OWASP:** A03:2025 Software Supply Chain Failures
- **Affected code:** `backend/uv.lock:1`, `.github/workflows/security.yml:1`, `package.json:7`
- **Problem:** Python dependencies had no reproducible lockfile and no automated security gate existed.
- **Attack scenario:** A future install could resolve a compromised or vulnerable transitive package without review.
- **Fix:** Added a hash-bearing `uv.lock`, reproducible `npm ci` and `uv sync --frozen` builds, pinned GitHub Action commit SHAs, weekly audits, Bandit, Ruff, pip-audit, npm audit, registry signature checks, tests, and production builds.

### LSP-SEC-10: Weak administrator session lifecycle

- **Severity:** Low
- **CWE:** CWE-613
- **OWASP:** A07:2025 Authentication Failures
- **Affected code:** `backend/app/api/admin.py:24`, `backend/app/api/admin.py:75`, `api/admin.js:17`, `api/admin.js:71`
- **Problem:** Administrator tokens lasted eight hours and lacked issuer, issued-at, and unique token identifiers. A short configured signing secret was accepted.
- **Attack scenario:** A stolen token remained useful for an extended period and had fewer validation constraints.
- **Fix:** Tokens now expire after two hours, require a valid issuer and lifetime, contain `iat` and random `jti` values, reject oversized tokens, re-check that the administrator remains configured, and require or safely derive at least 256 bits of signing material.

### LSP-SEC-11: Broad browser trust policy

- **Severity:** Low
- **CWE:** CWE-79, CWE-939
- **OWASP:** A02:2025 Security Misconfiguration
- **Affected code:** `vercel.json:18`, `frontend/src/App.jsx:1031`, `frontend/src/components/AssessmentDashboard.jsx:241`
- **Problem:** The CSP allowed connections to every Vercel application and external links trusted backend-provided schemes.
- **Attack scenario:** If untrusted data reached a link or a future script injection occurred, the browser had more outbound destinations than required.
- **Fix:** Production `connect-src` is same-origin, official learning references are restricted to approved HTTPS documentation hosts, and assessment links accept only HTTP or HTTPS.

### LSP-SEC-12: Error and exception information leakage

- **Severity:** Low
- **CWE:** CWE-209, CWE-703
- **OWASP:** A10:2025 Mishandling of Exceptional Conditions
- **Affected code:** `backend/app/engines/assessment/website.py:178`, `backend/app/engines/assessment/website.py:296`, `api/scans.js:806`
- **Problem:** Some raw network/TLS messages could be returned to users and broad exception handlers obscured failure classes.
- **Attack scenario:** Internal hostnames, library details, or deployment behavior could be disclosed while genuine exceptional states were silently ignored.
- **Fix:** External errors are generic, expected DNS/network exceptions are handled explicitly, operational failures are logged without sensitive URLs, and unexpected legacy errors return only `Scan failed`.

## Coverage

The audit reviewed authentication, authorization, sessions, BOLA/IDOR, input validation, output encoding, XSS, CSRF, SSRF, path traversal, file handling, command injection, SQL/NoSQL injection, LDAP/XML/XXE, SSTI, deserialization, CORS, CSP, cookies, JWT-like tokens, cryptography, logging, errors, rate limiting, denial of service, race conditions, unsafe redirects, cache behavior, request smuggling indicators, response splitting, prototype pollution, regular-expression denial of service, dependencies, secrets, Docker, CI/CD, Vercel, and environment handling.

The following classes are not implemented by this project and therefore had no reachable attack surface: raw SQL construction, NoSQL, LDAP, XML parsing, server templates, shell command execution, native memory management, file writes/uploads to disk, GraphQL, WebSockets, OAuth/OpenID, Kubernetes, mobile code, and outbound email. CSRF is not applicable to administrator actions because authentication uses an explicit bearer header rather than an automatically attached cookie.

## Remaining Risks

- Rate limiting is intentionally in memory so the project remains free. It resets on serverless cold starts and is not a replacement for edge-level abuse controls.
- Administrator tokens are stateless. Individual token revocation requires rotating `ADMIN_SESSION_SECRET`; the two-hour lifetime limits exposure.
- `style-src 'unsafe-inline'` remains because the existing visual system uses React inline CSS variables. Script execution remains restricted to same-origin files.
- Free Vercel SQLite storage is ephemeral. It protects confidentiality through owner checks but does not provide durable multi-instance history. A self-hosted PostgreSQL deployment is the free durable option.
- Public website scanning can still consume outbound bandwidth. Strict limits, public-IP pinning, response caps, concurrency caps, and timeouts reduce this operational risk.
- Container execution was statically reviewed, but Docker was not installed on the audit workstation, so images could not be built locally.

## Verification Evidence

- Python: 22 tests passed.
- JavaScript: 4 tests passed.
- Frontend: Vite production build passed.
- Ruff: no findings.
- Bandit: no findings.
- pip-audit: no known vulnerabilities.
- pip check: no broken requirements.
- Root npm audit: 0 vulnerabilities.
- Frontend npm audit: 0 vulnerabilities.
- npm registry integrity: 105 verified package signatures and 16 attestations across both lockfiles.
- Secret scan: no committed production credential and no administrator password in Git history. The local Vercel OIDC token remains ignored and was not committed.
- `git diff --check`: clean.

## Security References

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE Top 25:2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [SANS Top 25 Software Errors](https://www.sans.org/top25-software-errors)

## Maintenance Recommendations

1. Keep the weekly security workflow enabled and require it before merging.
2. Review dependency updates monthly and regenerate both lockfiles only from a clean working tree.
3. Rotate administrator credentials and `ADMIN_SESSION_SECRET` immediately after suspected disclosure.
4. Never put provider credentials in `VITE_*` variables because browser bundles are public.
5. Re-run this audit after adding authentication providers, file storage, a durable database, shell-based scanners, or new outbound integrations.
