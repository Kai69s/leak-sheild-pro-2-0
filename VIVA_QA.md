# LeakShield Pro Viva Questions and Answers

## 1. What problem does LeakShield Pro solve?

It detects leaked secrets in source code, environment files, deployment logs, and DevOps text before attackers can abuse them.

## 2. Why did you use FastAPI?

FastAPI supports async request handling, automatic OpenAPI documentation, Pydantic validation, and clean service separation.

## 3. Why PostgreSQL instead of SQLite?

PostgreSQL is production-grade, supports JSONB metadata, indexing, concurrency, and durable audit storage suitable for real security tools.

## 4. Why Redis?

Redis caches repeated scans by content hash and metadata hash, reducing duplicate scanning and database writes.

## 5. Are plaintext secrets stored?

No. LeakShield Pro stores SHA-256 hashes and obfuscated previews only.

## 6. How does the scoring system work?

Each finding starts from a severity weight, is multiplied by rule confidence, then adjusted by deployment and exposure context.

## 7. How is context handled?

The risk engine looks for high-risk terms like production, live, GitHub, public repo, and exposed, and lower-risk terms like test, dev, staging, sandbox, and local.

## 8. Does the project require AI?

No. The explanation engine is rule-based. The AI module is an optional future upgrade only.

## 9. How can new secret types be added?

Add a new `SecretRule` in `backend/app/engines/detection/rules.py` with regex, metadata, and remediation text.

## 10. What makes the architecture scalable?

Detection, risk scoring, explanation, API, database, and cache are separated into independent modules, making it easier to scale or replace components.

## 11. What are the main limitations?

Regex scanners can produce false positives and may miss highly unusual secret formats. The system reduces this with confidence scoring, context, and example filtering.

## 12. How would you deploy it?

Run the services with Docker Compose or deploy the backend, frontend, PostgreSQL, and Redis as separate production services behind an HTTPS reverse proxy.

