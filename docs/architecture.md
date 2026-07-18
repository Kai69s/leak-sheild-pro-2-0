# LeakShield Pro Architecture

## System Diagram

```text
Security Analyst / Developer
        |
        v
React Dashboard (Vite + Tailwind)
        |
        v
FastAPI REST API
        |
        v
Scan Service Orchestrator
        |
        +--> Detection Engine
        |       +--> AWS Key Rules
        |       +--> API Key Rules
        |       +--> Password Rules
        |       +--> Database URL Rules
        |       +--> Token Rules
        |       +--> Private Key Rules
        |
        +--> Risk Engine
        |       +--> Severity Weighting
        |       +--> Confidence Weighting
        |       +--> Context Adjustment
        |
        +--> Explanation Engine
        |       +--> Rule-Based Impact
        |       +--> Consequence Mapping
        |       +--> Remediation Guidance
        |
        +--> Website Assessment Engine
        |       +--> SSRF Guard + Bounded Crawler
        |       +--> Headers + TLS + DNS
        |       +--> CT Subdomains + RDAP
        |       +--> Technology + JavaScript Analysis
        |       +--> Public Exposure Verification Signals
        |       +--> OWASP/CWE/CAPEC Education
        |
        +--> Redis Cache
        |       +--> Repeated Scan Lookup
        |
        +--> PostgreSQL
                +--> Scan Audit Records
                +--> Finding Records
```

## Layer Explanation

The React dashboard is the user-facing analyst console. It provides a text editor, scan trigger, filterable results, risk visualization, and scan history without embedding detection logic in the browser.

The FastAPI REST API exposes stable endpoints for creating scans, listing history, and loading previous scans. FastAPI was selected because it supports async request handling, strong validation through Pydantic, and OpenAPI documentation.

The Scan Service is the application layer. It coordinates input validation, cache lookup, detection, risk scoring, explanation generation, database persistence, and response shaping.

The Detection Engine is modular. Each secret detector is defined as a rule with regex, severity, confidence, description, impact, consequence, and remediation. New rule modules can be added without changing API routes or UI code.

The Risk Engine converts findings into 0-100 scores. Base severity is weighted by rule confidence, then adjusted for context such as production, live, public repo, GitHub, test, dev, and staging.

The Explanation Engine is deterministic and rule-based. It explains what leaked, how an attacker can abuse it, likely real-world impact, and the operational remediation path.

The Website Assessment Engine performs bounded, passive checks of publicly reachable HTTP(S) resources. It blocks private, loopback, reserved, and local targets before every fetch and redirect. It uses only free standards and public sources: DNS, TLS, robots.txt, sitemap.xml, Certificate Transparency through crt.sh, and RDAP. Katana/Subfinder-style discovery is implemented natively for the Vercel runtime; self-hosted deployments can add optional CLI adapters later without making the core platform dependent on external binaries.

PostgreSQL stores durable scan and finding records for auditability, reporting, and historical review. Redis stores repeated scan results keyed by content hash and metadata to reduce duplicate CPU and database work.

## API Flow

```text
POST /api/scans
  -> validate payload size
  -> hash content and metadata
  -> return Redis hit if present
  -> run detection rules
  -> score each finding
  -> generate explanations
  -> persist scan and findings
  -> cache response
  -> return JSON
```

