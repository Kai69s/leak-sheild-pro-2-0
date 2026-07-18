export const knowledgeArticles = [
  {
    id: "security-headers",
    category: "Security Headers",
    title: "HTTP Security Headers",
    definition: "Response headers let a site instruct browsers to enforce security boundaries such as framing, content loading, transport, and referrer handling.",
    importance: "They reduce the impact of cross-site scripting, clickjacking, content-type confusion, and cross-origin data leaks.",
    detection: "Inspect the final HTTPS response for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy, COOP, COEP, and CORP.",
    mistakes: "Setting headers only on the homepage, using an unsafe CSP, or omitting headers from error responses.",
    mitigation: "Define policies centrally at the CDN, reverse proxy, or application middleware and test every response class.",
    references: [{ title: "OWASP Secure Headers Project", url: "https://owasp.org/www-project-secure-headers/" }]
  },
  {
    id: "tls-certificates",
    category: "Certificates",
    title: "TLS and Certificate Hygiene",
    definition: "TLS authenticates the server and encrypts traffic between a browser and the public application.",
    importance: "Weak protocols, ciphers, or expired certificates can expose credentials and destroy user trust.",
    detection: "Validate the certificate chain, issuer, hostname, expiration, negotiated TLS version, and cipher suite.",
    mistakes: "Manual renewal, allowing TLS 1.0/1.1, mixed HTTP content, and missing HSTS.",
    mitigation: "Automate renewal, require TLS 1.2+, prefer TLS 1.3, and redirect all HTTP traffic to HTTPS.",
    references: [{ title: "OWASP TLS Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html" }]
  },
  {
    id: "dns-email",
    category: "DNS",
    title: "DNS and Email Authentication",
    definition: "DNS records direct network traffic and publish sender-authentication policies such as SPF, DKIM, and DMARC.",
    importance: "Incorrect records can enable spoofing, takeover opportunities, mail abuse, and availability failures.",
    detection: "Resolve A, AAAA, MX, TXT, CAA, NS, CNAME, DNSKEY, SPF, DMARC, and common DKIM selectors.",
    mistakes: "Overly broad SPF, no DMARC policy, stale CNAMEs, and unmonitored nameservers.",
    mitigation: "Use restrictive records, remove stale entries, enable DNSSEC where supported, and monitor certificate issuance.",
    references: [{ title: "OWASP Domain Protection", url: "https://cheatsheetseries.owasp.org/cheatsheets/Domain_Protection_Cheat_Sheet.html" }]
  },
  {
    id: "secret-exposure",
    category: "Secrets",
    title: "Public Secret Exposure",
    definition: "A secret exposure occurs when credential material appears in public HTML, JavaScript, source maps, configuration, logs, or downloadable files.",
    importance: "A valid credential can allow direct access to cloud, databases, APIs, source code, or user sessions.",
    detection: "Pattern-match public textual content, verify context, redact values, and require manual confirmation before declaring a breach.",
    mistakes: "Putting secrets in frontend environment variables, committing .env files, or rotating without removing history.",
    mitigation: "Revoke first, rotate dependencies, remove the artifact, investigate use, and move credentials to server-side secret storage.",
    references: [{ title: "OWASP Secrets Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html" }]
  },
  {
    id: "api-security",
    category: "API Security",
    title: "Public API Surface",
    definition: "An API surface includes routes discovered in links, JavaScript bundles, documentation, and network-facing application behavior.",
    importance: "Undocumented routes often receive less testing and can expose sensitive operations or data.",
    detection: "Collect same-origin endpoints passively and classify them without attempting authorization bypass or exploitation.",
    mistakes: "Relying on hidden routes, trusting client-side authorization, and returning excessive fields.",
    mitigation: "Enforce server-side authorization per object and action, validate schemas, rate limit, and inventory every route.",
    references: [{ title: "OWASP API Security Top 10", url: "https://owasp.org/API-Security/" }]
  },
  {
    id: "authentication",
    category: "Authentication",
    title: "Authentication Controls",
    definition: "Authentication verifies identity before granting a session or credential.",
    importance: "Weak login, reset, and session controls can lead directly to account takeover.",
    detection: "Review public login/reset surfaces, cookie attributes, rate limits, session lifetime, and multi-factor support.",
    mistakes: "User enumeration, weak reset tokens, unlimited attempts, and long-lived bearer tokens.",
    mitigation: "Use established identity libraries, MFA, secure session cookies, generic errors, throttling, and token rotation.",
    references: [{ title: "OWASP Authentication Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" }]
  },
  {
    id: "authorization",
    category: "Authorization",
    title: "Authorization and Access Control",
    definition: "Authorization decides whether an authenticated or anonymous identity may perform a specific operation on a specific resource.",
    importance: "Missing object- or function-level checks are a leading cause of data exposure.",
    detection: "Map sensitive route categories and review server-side policy enforcement; passive scans do not bypass access controls.",
    mistakes: "Checking roles only in the UI, predictable identifiers, and default-allow policy.",
    mitigation: "Deny by default, centralize policy, verify ownership on every request, and test negative cases.",
    references: [{ title: "OWASP Authorization Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" }]
  },
  {
    id: "cors",
    category: "CORS",
    title: "Cross-Origin Resource Sharing",
    definition: "CORS tells browsers which external origins may read responses from a server.",
    importance: "An overly broad policy can expose authenticated data to an attacker-controlled site.",
    detection: "Inspect Access-Control response headers and test configuration logic with approved origins in a controlled environment.",
    mistakes: "Reflecting arbitrary origins, combining wildcard origins with credentials, and trusting Origin as authentication.",
    mitigation: "Use an exact allowlist, vary responses by Origin, avoid credentials when possible, and enforce authorization independently.",
    references: [{ title: "MDN CORS Guide", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS" }]
  },
  {
    id: "cookies",
    category: "Cookies",
    title: "Secure Session Cookies",
    definition: "Cookies commonly carry session identifiers and browser security attributes.",
    importance: "Missing Secure, HttpOnly, or SameSite controls can increase session theft and cross-site request risks.",
    detection: "Inspect Set-Cookie attributes without collecting or replaying session values.",
    mistakes: "Broad Domain scope, long expiration, missing rotation, and storing sensitive plaintext data in cookies.",
    mitigation: "Set Secure, HttpOnly, an appropriate SameSite policy, narrow Path/Domain, and short server-enforced expiration.",
    references: [{ title: "MDN Secure Cookie Configuration", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies" }]
  },
  {
    id: "subdomains",
    category: "Subdomains",
    title: "Subdomain Attack Surface",
    definition: "Subdomains expose separate applications, vendors, environments, and infrastructure under one organizational domain.",
    importance: "Forgotten hosts can run outdated software or retain dangling DNS records.",
    detection: "Combine Certificate Transparency and DNS results, deduplicate names, resolve addresses, and check basic HTTP availability.",
    mistakes: "Leaving dev/staging public, failing to remove vendor CNAMEs, and treating dead hosts as harmless.",
    mitigation: "Maintain an asset inventory, restrict non-production access, remove stale DNS, and monitor new certificates.",
    references: [{ title: "OWASP Attack Surface Analysis", url: "https://owasp.org/www-community/Attack_Surface_Analysis_Cheat_Sheet" }]
  },
  {
    id: "owasp-cwe",
    category: "OWASP",
    title: "OWASP, CWE, and CAPEC Mapping",
    definition: "OWASP categories describe common application risks, CWE classifies software weaknesses, and CAPEC catalogs generalized attack patterns.",
    importance: "Mappings give engineering and governance teams a shared language for prioritization and remediation.",
    detection: "Map each observed finding to the closest supported category while retaining the original technical evidence.",
    mistakes: "Treating a category as proof of exploitability or using compliance labels without technical context.",
    mitigation: "Use mappings for communication, then verify the exact control, evidence, likelihood, and business impact.",
    references: [{ title: "OWASP Top 10", url: "https://owasp.org/Top10/" }, { title: "MITRE CWE", url: "https://cwe.mitre.org/" }]
  }
];
