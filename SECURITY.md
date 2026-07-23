# Security Policy

## Supported Version

Security fixes are applied to the latest commit on `main`.

## Reporting A Vulnerability

Please do not publish credentials, personal data, or working exploit instructions in a public issue. Contact the repository owner privately with:

- The affected route or file
- The security impact
- Safe reproduction steps
- A suggested fix, if available

Reports should use test accounts and public demonstration targets only. LeakShield Pro is a defensive scanner and must not be used against systems without authorization.

## Security Guarantees

- No paid security service is required.
- Scan history is isolated by a random browser-session identifier.
- Detected secret values are hashed and redacted before storage.
- Website scans are restricted to validated public HTTP and HTTPS targets.
- Administrator credentials are supplied through server-only environment variables.

See `docs/security-audit-2026-07-23.md` for the latest full audit and remaining operational risks.
