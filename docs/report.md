# LeakShield Pro: DevSecOps Secret Detection System

## 1. Project Overview

LeakShield Pro is an industry-style cybersecurity final year project that detects leaked secrets in code snippets, configuration files, deployment logs, and DevOps text artifacts. It is built as a full-stack DevSecOps tool with a React dashboard, async FastAPI backend, modular detection engine, weighted threat scoring, context-aware risk adjustment, deterministic explanation engine, PostgreSQL persistence, and Redis caching.

## 2. Problem Statement

Modern software teams frequently expose secrets through source code, CI/CD logs, environment files, Docker configuration, and public repositories. Exposed secrets can allow attackers to access cloud infrastructure, databases, APIs, and private systems. LeakShield Pro solves this problem by scanning text before or after commit and producing actionable security intelligence.

## 3. Objectives

- Detect AWS keys, API keys, passwords, database URLs, bearer tokens, JWTs, and private keys.
- Score every finding from 0 to 100 and map it to LOW, MEDIUM, HIGH, or CRITICAL.
- Adjust scores using context such as production, live, GitHub, public repo, dev, test, and staging.
- Explain each finding in human-readable cybersecurity language without requiring AI APIs.
- Store audit-ready scan data in PostgreSQL.
- Cache repeated scans in Redis.
- Provide a professional dashboard for security review.

## 4. System Architecture

```text
User -> React Dashboard -> FastAPI API Gateway -> Scan Service
     -> Detection Engine -> Risk Engine -> Explanation Engine
     -> PostgreSQL + Redis -> API Response -> UI
```

The architecture separates presentation, API validation, orchestration, detection, scoring, explanation, persistence, and caching. This makes the system maintainable, testable, and scalable.

## 5. Backend Design

The backend uses Python 3.11 and FastAPI. Request handlers are async, database access uses SQLAlchemy Async with asyncpg, and Redis uses the async Redis client. The backend exposes:

- `GET /health`
- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`

The backend follows clean architecture principles by keeping route handlers thin and delegating business logic to services and engines.

## 6. Detection Engine

Detection rules are implemented as data-driven modules. Each rule contains a rule ID, secret type, severity, confidence, compiled regex, description, attacker impact, consequence, and remediation. This allows future extension without rewriting core scanner logic.

Supported detections:

- AWS access key IDs
- AWS secret access keys
- Generic API keys
- Password assignments
- PostgreSQL, MySQL, MariaDB, and MongoDB URLs
- Bearer tokens
- JWT tokens
- PEM private key blocks

## 7. Threat Scoring Model

The risk engine starts with severity weights:

- LOW: 20
- MEDIUM: 45
- HIGH: 70
- CRITICAL: 88

The base score is multiplied by rule confidence. Context then adjusts risk:

- production, prod, live, GitHub, public repo, exposed, and main branch increase risk.
- test, dev, development, staging, sandbox, and local reduce risk.
- direct authentication secrets such as private keys, database URLs, and AWS secret keys receive extra risk.

Final scores are bounded from 0 to 100.

## 8. Risk Levels

- 0-34: LOW
- 35-64: MEDIUM
- 65-84: HIGH
- 85-100: CRITICAL

## 9. Explanation Engine

LeakShield Pro does not require external AI. It generates deterministic explanations using rule metadata and risk adjustments. Every finding includes:

- what leaked
- attacker impact
- real-world consequence
- remediation guidance

## 10. Database Design

PostgreSQL tables:

### scans

- id
- source_name
- content_hash
- overall_score
- overall_level
- finding_count
- scan_metadata
- created_at

### findings

- id
- scan_id
- rule_id
- secret_type
- severity
- risk_score
- risk_level
- value_hash
- value_preview
- line_number
- column_start
- column_end
- context_snippet
- explanation
- created_at

Secrets are never stored in plaintext. The backend stores SHA-256 hashes and obfuscated previews only.

## 11. Redis Usage

Repeated scans are cached using a key generated from content hash, metadata hash, and source name. This improves performance for repeated submissions and reduces unnecessary database writes.

## 12. Frontend Design

The frontend is a React dashboard styled with Tailwind CSS. It includes:

- code/text editor
- scan button
- overall risk meter
- findings cards
- categorized risk badges
- scan history
- search and filtering
- responsive dark cybersecurity theme

## 13. Security Considerations

- Plaintext secrets are not persisted.
- Input size is limited.
- CORS is configurable.
- Findings are hashed and obfuscated.
- Context is escaped before returning snippets.
- Backend logic is server-side and not trusted to the browser.

## 14. Testing

A backend unit test verifies detection and risk scoring for a production password leak. Additional tests can be added for each rule and API endpoint.

## 15. Viva Defense Summary

LeakShield Pro demonstrates DevSecOps, secure coding, async backend development, database design, caching, modular rule engineering, risk modeling, and full-stack dashboard development. It is suitable for university submission and portfolio demonstration because it is functional, extensible, and based on real security workflows.

## 16. Conclusion

LeakShield Pro addresses a real cybersecurity problem: accidental secret leakage. It detects multiple secret classes, scores their threat level, explains attacker impact, stores audit trails, and gives developers a practical dashboard for remediation.

## 17. Optional AI Upgrade

An optional AI explainer can be added later to rewrite or enrich explanations. The core system does not depend on AI and remains fully operational without model keys, external APIs, or network-based inference.

