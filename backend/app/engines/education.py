from typing import Any


OFFICIAL_REFERENCES = {
    "headers": [
        {"title": "OWASP Secure Headers Project", "url": "https://owasp.org/www-project-secure-headers/"},
        {"title": "MDN HTTP Headers", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"},
    ],
    "secrets": [
        {"title": "OWASP Secrets Management Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"},
        {"title": "CWE-798 Hard-coded Credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"},
    ],
    "tls": [
        {"title": "OWASP Transport Layer Security Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"},
        {"title": "MDN Transport Layer Security", "url": "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"},
    ],
    "dns": [
        {"title": "OWASP Domain Protection Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Domain_Protection_Cheat_Sheet.html"},
        {"title": "RFC 7489 DMARC", "url": "https://www.rfc-editor.org/rfc/rfc7489"},
    ],
    "exposure": [
        {"title": "OWASP Web Security Testing Guide", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
        {"title": "CWE-200 Exposure of Sensitive Information", "url": "https://cwe.mitre.org/data/definitions/200.html"},
    ],
}


def learning_guide(title: str, category: str, impact: str, remediation: str) -> dict[str, Any]:
    subject = title.lower()
    return {
        "definition": f"{title} is a security condition detected from publicly observable application behavior or content.",
        "why_dangerous": impact,
        "attacker_method": f"An attacker may use automated reconnaissance to identify {subject} and combine it with other weaknesses. LeakShield does not attempt exploitation.",
        "real_world_example": "A generalized incident begins with public reconnaissance, followed by unauthorized access or data exposure when defensive controls are missing.",
        "business_impact": impact,
        "common_mistakes": [
            "Relying on obscurity instead of an explicit security control.",
            "Applying a fix only in development while production remains unchanged.",
            "Skipping verification after deployment.",
        ],
        "remediation_steps": [
            remediation,
            "Deploy the change to a non-production environment first.",
            "Re-scan the public endpoint and add a regression check to CI.",
        ],
        "best_practices": [
            "Use least privilege and defense in depth.",
            "Keep security configuration version controlled and peer reviewed.",
            "Monitor for regressions after every release.",
        ],
        "secure_coding": [
            "Centralize security configuration instead of duplicating it across routes.",
            "Fail closed when a required security control cannot be loaded.",
        ],
        "prevention_checklist": [
            "Owner assigned",
            "Fix reviewed",
            "Automated test added",
            "Production verified",
            "Monitoring enabled",
        ],
        "references": OFFICIAL_REFERENCES.get(category, OFFICIAL_REFERENCES["exposure"]),
    }


def developer_fixes(header: str | None = None, value: str | None = None) -> dict[str, Any]:
    if header and value:
        snippets = {
            "Nginx": f'add_header {header} "{value}" always;',
            "Apache": f'Header always set {header} "{value}"',
            "Express.js": f'app.use((req, res, next) => {{ res.setHeader("{header}", "{value}"); next(); }});',
            "Next.js": f'// next.config.js\nasync headers() {{ return [{{ source: "/:path*", headers: [{{ key: "{header}", value: "{value}" }}] }}]; }}',
            "Laravel": f'// SecurityHeaders middleware\n$response->headers->set("{header}", "{value}");',
            "Spring Boot": f'http.headers(headers -> headers.addHeaderWriter((request, response) -> response.setHeader("{header}", "{value}")));',
        }
        return {"generic": f"Set {header} at the edge or application layer and verify it on every response.", "snippets": snippets}
    return {
        "generic": "Remove the exposed value, rotate it at the provider, move it to a server-side secret store, and verify repository history.",
        "snippets": {
            "Node.js": 'const token = process.env.SERVICE_TOKEN;\nif (!token) throw new Error("SERVICE_TOKEN is required");',
            "React": "Never place secrets in client bundles or variables exposed at build time.",
            "Next.js": "Read secrets only in Server Components, Route Handlers, or server actions.",
            "Laravel": "$token = config('services.vendor.token'); // backed by server environment",
            "Spring Boot": "Use an environment-backed @ConfigurationProperties secret and exclude it from actuator output.",
        },
    }


def mapping_for(category: str) -> tuple[str, str, str | None]:
    mappings = {
        "headers": ("A05:2021 Security Misconfiguration", "CWE-693", "CAPEC-115"),
        "secrets": ("A07:2021 Identification and Authentication Failures", "CWE-798", "CAPEC-560"),
        "tls": ("A02:2021 Cryptographic Failures", "CWE-326", "CAPEC-94"),
        "dns": ("A05:2021 Security Misconfiguration", "CWE-16", None),
        "exposure": ("A01:2021 Broken Access Control", "CWE-200", "CAPEC-116"),
    }
    return mappings.get(category, mappings["exposure"])
