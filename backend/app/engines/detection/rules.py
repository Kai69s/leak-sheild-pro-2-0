from dataclasses import dataclass
import re


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    secret_type: str
    severity: str
    confidence: float
    pattern: re.Pattern[str]
    description: str
    attacker_impact: str
    consequence: str
    remediation: str


def compile_rule(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.MULTILINE)


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        rule_id="aws-access-key-id",
        secret_type="AWS Access Key ID",
        severity="HIGH",
        confidence=0.95,
        pattern=compile_rule(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        description="An AWS access key identifier was exposed.",
        attacker_impact="Attackers can pair it with a secret key to access AWS APIs.",
        consequence="Cloud resources, S3 data, IAM permissions, and billing can be abused.",
        remediation="Disable the access key, rotate credentials, and audit CloudTrail activity.",
    ),
    SecretRule(
        rule_id="aws-secret-access-key",
        secret_type="AWS Secret Access Key",
        severity="CRITICAL",
        confidence=0.9,
        pattern=compile_rule(
            r"(?i)(?:aws(.{0,20})?(?:secret|private)?(.{0,20})?(?:key))\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"
        ),
        description="An AWS secret access key value was exposed.",
        attacker_impact="Attackers may authenticate directly to AWS services.",
        consequence="This can lead to infrastructure takeover, data theft, and financial loss.",
        remediation="Revoke the key immediately, rotate dependent secrets, and review IAM policy scope.",
    ),
    SecretRule(
        rule_id="generic-api-key",
        secret_type="API Key",
        severity="MEDIUM",
        confidence=0.75,
        pattern=compile_rule(
            r"(?i)\b(api[_-]?key|apikey|x-api-key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,96})"
        ),
        description="A generic API key was found in source or configuration text.",
        attacker_impact="Attackers can call the associated service as the leaked identity.",
        consequence="Quota abuse, data access, account takeover, or service disruption may occur.",
        remediation="Rotate the API key and move it to a managed secret store.",
    ),
    SecretRule(
        rule_id="password-assignment",
        secret_type="Password",
        severity="HIGH",
        confidence=0.7,
        pattern=compile_rule(
            r"(?i)\b(password|passwd|pwd|db_password)\b\s*[:=]\s*[\"']([^\"'\s]{8,128})[\"']?"
        ),
        description="A hardcoded password-like assignment was detected.",
        attacker_impact="Attackers can authenticate to the protected account or system.",
        consequence="Credential reuse may expand the breach to databases, apps, or admin panels.",
        remediation="Change the password, invalidate active sessions, and store secrets outside code.",
    ),
    SecretRule(
        rule_id="database-url",
        secret_type="Database URL",
        severity="CRITICAL",
        confidence=0.88,
        pattern=compile_rule(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?)://[^\s\"']+:[^\s\"']+@[^\s\"']+"
        ),
        description="A database connection string containing credentials was exposed.",
        attacker_impact="Attackers can connect to the database if network access is available.",
        consequence="Sensitive records may be read, modified, deleted, or ransomed.",
        remediation="Rotate database credentials, restrict network access, and review database logs.",
    ),
    SecretRule(
        rule_id="bearer-token",
        secret_type="Bearer Token",
        severity="HIGH",
        confidence=0.8,
        pattern=compile_rule(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{24,2048})"),
        description="A bearer token was exposed.",
        attacker_impact="Attackers can replay the token until it expires or is revoked.",
        consequence="API sessions, user data, and privileged workflows may be compromised.",
        remediation="Revoke the token, shorten token lifetime, and rotate signing keys if needed.",
    ),
    SecretRule(
        rule_id="jwt-token",
        secret_type="JWT Token",
        severity="HIGH",
        confidence=0.85,
        pattern=compile_rule(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        description="A JSON Web Token was found.",
        attacker_impact="Attackers can impersonate the token subject if the token is valid.",
        consequence="Application sessions and API authorizations may be abused.",
        remediation="Revoke the token, rotate affected signing secrets, and review session logs.",
    ),
    SecretRule(
        rule_id="private-key-block",
        secret_type="Private Key",
        severity="CRITICAL",
        confidence=0.98,
        pattern=compile_rule(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        description="A private cryptographic key block was exposed.",
        attacker_impact="Attackers can decrypt traffic, sign payloads, or access servers depending on key use.",
        consequence="SSH access, TLS trust, package signing, or encrypted data may be compromised.",
        remediation="Replace the key pair, remove it from history, and rotate all dependent trust.",
    ),
)

