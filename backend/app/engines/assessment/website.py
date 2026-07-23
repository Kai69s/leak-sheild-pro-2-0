import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import dns.asyncresolver
import dns.exception
import httpx
from fastapi import HTTPException

from app.engines.detection import DetectionEngine
from app.engines.education import developer_fixes, learning_guide, mapping_for
from app.engines.explanation import ExplanationEngine
from app.engines.risk import RiskEngine


MAX_RESPONSE_BYTES = 600_000
MAX_PAGES = 20
MAX_JAVASCRIPT_FILES = 8
COMMON_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/login",
    "/admin",
    "/dashboard",
    "/api",
    "/api/docs",
    "/docs",
    "/reset-password",
    "/.well-known/security.txt",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/database.sql",
    "/config.json",
)
EXPOSURE_PATHS = {"/.env", "/.git/config", "/backup.zip", "/database.sql", "/config.json"}
HEADER_RULES = (
    ("content-security-policy", "Content-Security-Policy", "HIGH", "default-src 'self'; object-src 'none'; base-uri 'self'"),
    ("strict-transport-security", "Strict-Transport-Security", "HIGH", "max-age=31536000; includeSubDomains"),
    ("x-frame-options", "X-Frame-Options", "MEDIUM", "DENY"),
    ("x-content-type-options", "X-Content-Type-Options", "MEDIUM", "nosniff"),
    ("permissions-policy", "Permissions-Policy", "LOW", "camera=(), microphone=(), geolocation=()"),
    ("referrer-policy", "Referrer-Policy", "LOW", "strict-origin-when-cross-origin"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "MEDIUM", "same-origin"),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy", "LOW", "require-corp"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy", "LOW", "same-origin"),
)
SEVERITY_SCORE = {"LOW": 20.0, "MEDIUM": 45.0, "HIGH": 72.0, "CRITICAL": 92.0}
logger = logging.getLogger(__name__)


class LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "link", "form"}:
            candidate = values.get("href") or values.get("action")
            if candidate:
                self.links.add(candidate)
        if tag == "script" and values.get("src"):
            self.scripts.add(values["src"] or "")
        if tag == "meta" and (values.get("name") or "").lower() == "generator" and values.get("content"):
            self.generators.append(values["content"] or "")


def _clean_url(value: str) -> str:
    parsed = urlparse(value.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="A public http or https website URL is required")
    try:
        host = parsed.hostname.encode("idna").decode()
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise HTTPException(status_code=400, detail="The website URL contains an invalid host or port") from error
    netloc_host = f"[{host}]" if ":" in host else host
    netloc = netloc_host if not port else f"{netloc_host}:{port}"
    # Query values can contain credentials and are unnecessary for this passive path assessment.
    return urlunparse((scheme, netloc, parsed.path or "/", "", "", ""))


def _is_global_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.split("%")[0]).is_global
    except ValueError:
        return False


async def _resolve_public_target(value: str) -> tuple[str, str]:
    safe_url = _clean_url(value)
    hostname = urlparse(safe_url).hostname or ""
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith((".local", ".internal")):
        raise HTTPException(status_code=400, detail="Private and local network targets are not allowed")
    try:
        addresses = await asyncio.to_thread(socket.getaddrinfo, hostname, None, type=socket.SOCK_STREAM)
    except OSError as error:
        raise HTTPException(status_code=400, detail="The target hostname could not be resolved") from error
    ips = {item[4][0].split("%")[0] for item in addresses}
    if not ips or any(not _is_global_address(address) for address in ips):
        raise HTTPException(status_code=400, detail="Private, reserved, and loopback targets are not allowed")
    return safe_url, sorted(ips)[0]


async def _assert_public_url(value: str) -> str:
    safe_url, _address = await _resolve_public_target(value)
    return safe_url


def _pinned_request(safe_url: str, address: str) -> tuple[str, dict[str, str], dict[str, str]]:
    parsed = urlparse(safe_url)
    address_host = f"[{address}]" if ":" in address else address
    netloc = address_host if not parsed.port else f"{address_host}:{parsed.port}"
    request_url = urlunparse((parsed.scheme, netloc, parsed.path or "/", "", "", ""))
    headers = {"Host": parsed.netloc}
    extensions = {"sni_hostname": parsed.hostname or ""}
    return request_url, headers, extensions


def _same_origin(candidate: str, origin: str) -> bool:
    left = urlparse(candidate)
    right = urlparse(origin)
    return left.scheme == right.scheme and left.netloc == right.netloc


def _absolute(base: str, candidate: str) -> str | None:
    if not candidate or candidate.startswith(("data:", "mailto:", "tel:", "javascript:", "#")):
        return None
    try:
        value = _clean_url(urljoin(base, candidate))
        return value if _same_origin(value, base) else None
    except (HTTPException, ValueError):
        return None


async def _fetch(client: httpx.AsyncClient, url: str, redirects: int = 0) -> dict[str, Any]:
    safe_url, address = await _resolve_public_target(url)
    request_url, headers, extensions = _pinned_request(safe_url, address)
    try:
        async with client.stream("GET", request_url, headers=headers, extensions=extensions) as response:
            _assert_public_peer(response)
            if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("location"):
                if redirects >= 3:
                    raise HTTPException(status_code=400, detail="The target redirected too many times")
                return await _fetch(client, urljoin(safe_url, response.headers["location"]), redirects + 1)
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > MAX_RESPONSE_BYTES:
                    break
            content_type = response.headers.get("content-type", "").lower()
            textual = any(item in content_type for item in ("text", "json", "javascript", "xml")) or not content_type
            text = bytes(chunks[:MAX_RESPONSE_BYTES]).decode(response.encoding or "utf-8", errors="replace") if textual else ""
            return {
                "url": safe_url,
                "status": response.status_code,
                "headers": dict(response.headers),
                "content_type": content_type,
                "text": text,
                "truncated": len(chunks) > MAX_RESPONSE_BYTES,
            }
    except httpx.TimeoutException as error:
        raise HTTPException(status_code=504, detail=f"Timed out while requesting {urlparse(safe_url).path or '/'}") from error
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail="The public target could not be fetched") from error


def _assert_public_peer(response: httpx.Response) -> None:
    network_stream = response.extensions.get("network_stream")
    peer = network_stream.get_extra_info("server_addr") if network_stream else None
    if not peer:
        return
    peer_ip = str(peer[0] if isinstance(peer, tuple) else peer).split("%")[0]
    if not _is_global_address(peer_ip):
        raise HTTPException(status_code=400, detail="The target connected to a non-public network address")


def _header_assessment(headers: dict[str, str]) -> list[dict[str, Any]]:
    normalized = {key.lower(): value for key, value in headers.items()}
    results = []
    for key, label, severity, recommended in HEADER_RULES:
        present = bool(normalized.get(key))
        results.append(
            {
                "name": label,
                "present": present,
                "value": normalized.get(key),
                "risk": "LOW" if present else severity,
                "recommendation": "Header is present; review its policy during releases." if present else f"Set {label} to a policy appropriate for the application.",
                "recommended_value": recommended,
            }
        )
    return results


def _technology_assessment(text: str, headers: dict[str, str], collector: LinkCollector) -> list[dict[str, str]]:
    blob = f"{text[:300_000]} {json.dumps(headers)} {' '.join(collector.generators)}".lower()
    signatures = {
        "React": ("react", "__react", "data-reactroot"),
        "Next.js": ("__next_data__", "/_next/", "next.js"),
        "Vue": ("data-v-", "__vue__", "vue.js"),
        "Angular": ("ng-version", "angular.js", "ng-app"),
        "Laravel": ("laravel_session", "laravel"),
        "Express": ("x-powered-by\": \"express", "express"),
        "Apache": ("apache",),
        "Nginx": ("nginx",),
        "Cloudflare": ("cf-ray", "cloudflare"),
        "WordPress": ("wp-content", "wp-includes", "wordpress"),
        "Bootstrap": ("bootstrap.min.css", "bootstrap.css"),
        "Tailwind CSS": ("tailwind", "--tw-"),
    }
    return [
        {"name": name, "confidence": "high" if sum(marker in blob for marker in markers) > 1 else "medium"}
        for name, markers in signatures.items()
        if any(marker in blob for marker in markers)
    ]


async def _dns_assessment(hostname: str) -> dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    records: dict[str, list[str]] = {}
    for record_type in ("A", "AAAA", "MX", "TXT", "CAA", "NS", "CNAME"):
        try:
            answer = await resolver.resolve(hostname, record_type, lifetime=2.5)
            records[record_type] = [str(item).strip('"') for item in answer]
        except dns.exception.DNSException:
            records[record_type] = []
    txt = records["TXT"]
    records["SPF"] = [item for item in txt if item.lower().startswith("v=spf1")]
    try:
        dmarc = await resolver.resolve(f"_dmarc.{hostname}", "TXT", lifetime=2.5)
        records["DMARC"] = [str(item).strip('"') for item in dmarc]
    except dns.exception.DNSException:
        records["DMARC"] = []
    dkim_records = []
    for selector in ("default", "google", "selector1", "selector2"):
        try:
            answer = await resolver.resolve(f"{selector}._domainkey.{hostname}", "TXT", lifetime=1.5)
            dkim_records.extend(f"{selector}: {str(item).strip(chr(34))}" for item in answer)
        except dns.exception.DNSException:
            continue
    records["DKIM"] = dkim_records
    try:
        await resolver.resolve(hostname, "DNSKEY", lifetime=2.5)
        dnssec = True
    except dns.exception.DNSException:
        dnssec = False
    return {"records": records, "dnssec": dnssec}


def _ssl_sync(hostname: str, address: str, port: int) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((address, port), timeout=5) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as secure_socket:
            certificate = secure_socket.getpeercert()
            expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            issuer = {key: value for group in certificate.get("issuer", ()) for key, value in group}
            cipher = secure_socket.cipher() or (None, None, None)
            return {
                "valid": True,
                "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown",
                "subject": dict(item[0] for item in certificate.get("subject", ())).get("commonName"),
                "expires_at": expires.isoformat(),
                "days_remaining": max(0, (expires - datetime.now(timezone.utc)).days),
                "tls_version": secure_socket.version(),
                "cipher": cipher[0],
                "cipher_bits": cipher[2],
                "weak_configuration": secure_socket.version() in {"TLSv1", "TLSv1.1"} or (cipher[2] or 0) < 128,
            }


async def _ssl_assessment(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"valid": False, "error": "The target does not use HTTPS", "days_remaining": 0, "weak_configuration": True}
    try:
        safe_url, address = await _resolve_public_target(url)
        safe_host = urlparse(safe_url).hostname or ""
        return await asyncio.to_thread(_ssl_sync, safe_host, address, parsed.port or 443)
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return {
            "valid": False,
            "error": "TLS negotiation or certificate validation failed",
            "days_remaining": 0,
            "weak_configuration": True,
        }


async def _subdomain_assessment(client: httpx.AsyncClient, hostname: str) -> list[dict[str, Any]]:
    root = hostname[4:] if hostname.startswith("www.") else hostname
    names = {hostname, *(f"{prefix}.{root}" for prefix in ("www", "api", "admin", "dev", "staging", "mail"))}
    try:
        response = await client.get("https://crt.sh/", params={"q": f"%.{root}", "output": "json"}, timeout=5)
        if response.status_code == 200:
            for item in response.json()[:200]:
                for name in str(item.get("name_value", "")).splitlines():
                    clean = name.lower().removeprefix("*.").strip()
                    if clean == root or clean.endswith(f".{root}"):
                        names.add(clean)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError):
        logger.info("Certificate Transparency lookup unavailable")

    resolver_slots = asyncio.Semaphore(5)

    async def inspect(name: str) -> dict[str, Any]:
        async with resolver_slots:
            try:
                addresses = await asyncio.to_thread(socket.getaddrinfo, name, None, type=socket.SOCK_STREAM)
                ips = sorted({item[4][0] for item in addresses})
            except OSError:
                return {"hostname": name, "alive": False, "status": None, "ips": [], "technology": None, "ssl": None}
            if not ips or any(not _is_global_address(address) for address in ips):
                return {
                    "hostname": name,
                    "alive": False,
                    "status": None,
                    "ips": [],
                    "technology": None,
                    "ssl": None,
                    "blocked": True,
                }
            status = None
            server = None
            tls = False
            for scheme in ("https", "http"):
                try:
                    safe_url = f"{scheme}://{name}/"
                    request_url, headers, extensions = _pinned_request(safe_url, ips[0])
                    async with client.stream(
                        "GET",
                        request_url,
                        headers=headers,
                        extensions=extensions,
                        timeout=2.5,
                    ) as response:
                        _assert_public_peer(response)
                        status = response.status_code
                        server = response.headers.get("server")
                        tls = scheme == "https"
                        break
                except (HTTPException, httpx.HTTPError):
                    continue
        return {"hostname": name, "alive": status is not None, "status": status, "ips": ips, "technology": server, "ssl": tls}

    selected = sorted(names)[:30]
    return list(await asyncio.gather(*(inspect(name) for name in selected)))


async def _threat_intelligence(client: httpx.AsyncClient, hostname: str) -> dict[str, Any]:
    try:
        ip = (await asyncio.to_thread(socket.getaddrinfo, hostname, None, type=socket.SOCK_STREAM))[0][4][0]
    except (OSError, IndexError):
        return {}
    try:
        reverse_dns = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
    except OSError:
        reverse_dns = None
    result: dict[str, Any] = {"ip": ip, "reverse_dns": reverse_dns}
    try:
        response = await client.get(f"https://rdap.org/ip/{ip}", timeout=4)
        if response.status_code == 200:
            data = response.json()
            result.update(
                {
                    "asn_name": data.get("name"),
                    "handle": data.get("handle"),
                    "country": data.get("country"),
                    "network": f"{data.get('startAddress', '')} - {data.get('endAddress', '')}",
                    "whois_summary": data.get("remarks", [{}])[0].get("description", [None])[0] if data.get("remarks") else None,
                }
            )
    except (httpx.HTTPError, json.JSONDecodeError, ValueError, IndexError, TypeError):
        logger.info("RDAP lookup unavailable")
        return result
    return result


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    summary: str,
    remediation: str,
    address: str,
    header: str | None = None,
    header_value: str | None = None,
) -> dict[str, Any]:
    score = SEVERITY_SCORE[severity]
    owasp, cwe, capec = mapping_for(category)
    impact = summary
    return {
        "rule_id": rule_id,
        "secret_type": title,
        "severity": severity,
        "risk_score": score,
        "risk_level": severity,
        "value_hash": hashlib.sha256(f"{rule_id}:{address}".encode()).hexdigest(),
        "value_preview": "Configuration finding",
        "line_number": 1,
        "column_start": 1,
        "column_end": 1,
        "context_snippet": address,
        "source_address": address,
        "public_accessible": True,
        "confidence": 0.95,
        "owasp": owasp,
        "cwe": cwe,
        "capec": capec,
        "explanation": {
            "summary": summary,
            "attacker_impact": impact,
            "real_world_consequence": impact,
            "business_impact": impact,
            "remediation": remediation,
            "learning": learning_guide(title, category, impact, remediation),
            "developer_fixes": developer_fixes(header, header_value),
        },
    }


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"


class WebsiteAssessmentEngine:
    def __init__(self) -> None:
        self.detector = DetectionEngine()
        self.risk_engine = RiskEngine()
        self.explainer = ExplanationEngine()

    async def assess(self, raw_url: str) -> dict[str, Any]:
        start_url = await _assert_public_url(raw_url)
        timeout = httpx.Timeout(7.0, connect=4.0)
        limits = httpx.Limits(max_connections=8, max_keepalive_connections=4)
        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            headers={"User-Agent": "LeakShield-Pro/2.0 (+defensive-public-security-assessment)"},
        ) as client:
            homepage = await _fetch(client, start_url)
            canonical = homepage["url"]
            parsed = urlparse(canonical)
            hostname = parsed.hostname or ""
            collector = LinkCollector()
            collector.feed(homepage["text"])
            queue = {canonical, *(urljoin(canonical, path) for path in COMMON_PATHS)}
            queue.update(filter(None, (_absolute(canonical, link) for link in collector.links)))
            queue.update(filter(None, (_absolute(canonical, script) for script in collector.scripts)))

            fetched: list[dict[str, Any]] = [homepage]
            seen = {canonical}
            pending = list(queue)
            while pending and len(fetched) < MAX_PAGES:
                url = pending.pop(0)
                if url in seen:
                    continue
                seen.add(url)
                try:
                    result = await _fetch(client, url)
                    fetched.append(result)
                    if "html" in result["content_type"] and result["status"] < 400:
                        nested = LinkCollector()
                        nested.feed(result["text"])
                        for link in nested.links:
                            absolute = _absolute(canonical, link)
                            if absolute and len(queue) < MAX_PAGES * 4:
                                queue.add(absolute)
                                pending.append(absolute)
                    path = urlparse(result["url"]).path
                    discovered_paths = []
                    if path == "/robots.txt":
                        discovered_paths.extend(
                            match.strip()
                            for match in re.findall(r"(?im)^(?:allow|disallow):\s*([^#\s]+)", result["text"])
                        )
                        discovered_paths.extend(re.findall(r"(?im)^sitemap:\s*(https?://\S+)", result["text"]))
                    if "sitemap" in path:
                        discovered_paths.extend(re.findall(r"(?is)<loc>\s*([^<]+)\s*</loc>", result["text"]))
                    for discovered in discovered_paths[:40]:
                        absolute = _absolute(canonical, discovered)
                        if absolute and absolute not in queue and len(queue) < MAX_PAGES * 4:
                            queue.add(absolute)
                            pending.append(absolute)
                except HTTPException:
                    continue

            headers = _header_assessment(homepage["headers"])
            technologies = _technology_assessment(homepage["text"], homepage["headers"], collector)
            dns_task = asyncio.create_task(_dns_assessment(hostname))
            ssl_task = asyncio.create_task(_ssl_assessment(canonical))
            subdomains_task = asyncio.create_task(_subdomain_assessment(client, hostname))
            intel_task = asyncio.create_task(_threat_intelligence(client, hostname))

            endpoints = []
            javascript = {"files": [], "endpoints": [], "source_maps": [], "potential_secrets": 0}
            findings = []
            homepage_hash = hashlib.sha256(homepage["text"].encode()).hexdigest()
            for item in fetched:
                path = urlparse(item["url"]).path or "/"
                kind = "javascript" if "javascript" in item["content_type"] or path.endswith(".js") else "page"
                if path == "/robots.txt":
                    kind = "robots"
                elif "sitemap" in path:
                    kind = "sitemap"
                endpoints.append(
                    {
                        "url": item["url"],
                        "path": path,
                        "status": item["status"],
                        "type": kind,
                        "content_type": item["content_type"],
                        "source": "crawler" if path not in COMMON_PATHS else "security-probe",
                    }
                )
                if kind == "javascript" and len(javascript["files"]) < MAX_JAVASCRIPT_FILES:
                    javascript["files"].append(item["url"])
                    discovered = re.findall(r"[\"']((?:/|https?://)[A-Za-z0-9_./?=&%:-]{3,})[\"']", item["text"])
                    javascript["endpoints"].extend(discovered[:80])
                    if re.search(r"sourceMappingURL=", item["text"]):
                        javascript["source_maps"].append(item["url"])
                if path in EXPOSURE_PATHS and item["status"] == 200 and item["text"]:
                    content_hash = hashlib.sha256(item["text"].encode()).hexdigest()
                    if content_hash != homepage_hash:
                        findings.append(
                            _finding(
                                f"public-exposure-{path.strip('/').replace('/', '-')}",
                                f"Potential public exposure at {path}",
                                "CRITICAL" if path in {"/.env", "/.git/config", "/database.sql"} else "HIGH",
                                "exposure",
                                "A sensitive-looking file path returned distinct public content and requires immediate manual verification.",
                                "Restrict the path at the web server, remove the artifact from the deployment, and rotate any data it contained.",
                                item["url"],
                            )
                        )
                if item["text"]:
                    for detection in self.detector.scan(item["text"]):
                        risk = self.risk_engine.score_finding(detection, item["text"], {"website": True, "public": True})
                        explanation = self.explainer.explain(detection, risk)
                        explanation.update(
                            {
                                "business_impact": detection.rule.consequence,
                                "learning": learning_guide(detection.rule.secret_type, "secrets", detection.rule.consequence, detection.rule.remediation),
                                "developer_fixes": developer_fixes(),
                            }
                        )
                        owasp, cwe, capec = mapping_for("secrets")
                        findings.append(
                            {
                                "rule_id": detection.rule.rule_id,
                                "secret_type": f"Potential {detection.rule.secret_type}",
                                "severity": detection.rule.severity,
                                "risk_score": risk.score,
                                "risk_level": risk.level,
                                "value_hash": detection.value_hash,
                                "value_preview": detection.value_preview,
                                "line_number": detection.line_number,
                                "column_start": detection.column_start,
                                "column_end": detection.column_end,
                                "context_snippet": detection.context_snippet,
                                "source_address": item["url"],
                                "public_accessible": True,
                                "confidence": detection.rule.confidence,
                                "owasp": owasp,
                                "cwe": cwe,
                                "capec": capec,
                                "explanation": explanation,
                            }
                        )

            for item in headers:
                if not item["present"]:
                    findings.append(
                        _finding(
                            f"missing-{item['name'].lower()}",
                            f"Missing {item['name']}",
                            item["risk"],
                            "headers",
                            f"The {item['name']} response header is missing from the public homepage.",
                            item["recommendation"],
                            canonical,
                            item["name"],
                            item["recommended_value"],
                        )
                    )

            dns_data, ssl_data, subdomains, threat_intel = await asyncio.gather(
                dns_task, ssl_task, subdomains_task, intel_task
            )
            if not ssl_data.get("valid") or ssl_data.get("weak_configuration"):
                findings.append(
                    _finding(
                        "weak-transport-security",
                        "Weak or unavailable TLS configuration",
                        "HIGH",
                        "tls",
                        ssl_data.get("error") or "The negotiated TLS configuration is outdated or weak.",
                        "Use HTTPS everywhere with TLS 1.2 or newer, modern ciphers, and automated certificate renewal.",
                        canonical,
                    )
                )
            elif ssl_data.get("days_remaining", 365) < 30:
                findings.append(
                    _finding(
                        "certificate-expiring-soon",
                        "TLS certificate expires soon",
                        "MEDIUM",
                        "tls",
                        f"The certificate has {ssl_data['days_remaining']} day(s) remaining.",
                        "Renew the certificate and verify automated renewal before the remaining window closes.",
                        canonical,
                    )
                )
            if dns_data["records"].get("MX") and not dns_data["records"].get("DMARC"):
                findings.append(
                    _finding(
                        "missing-dmarc",
                        "Missing DMARC policy",
                        "MEDIUM",
                        "dns",
                        "The domain receives email but no DMARC TXT policy was discovered.",
                        "Publish a monitored DMARC policy, validate legitimate senders, then move toward quarantine or reject.",
                        f"_dmarc.{hostname}",
                    )
                )

            deduped = {f"{item['rule_id']}:{item.get('source_address')}:{item['value_hash']}": item for item in findings}
            findings = sorted(deduped.values(), key=lambda item: item["risk_score"], reverse=True)[:500]
            risks = [item["risk_score"] for item in findings]
            overall_risk = round(min(100, (max(risks) if risks else 0) + min(10, max(0, len(risks) - 1))), 1)
            security_score = round(max(0, 100 - overall_risk), 1)
            risk_level = RiskEngine.level_for_score(overall_risk)
            grade = _grade(security_score)
            by_priority = []
            for index, severity in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW"), start=1):
                related = [item for item in findings if item["risk_level"] == severity]
                if related:
                    by_priority.append(
                        {
                            "priority": index,
                            "severity": severity,
                            "title": f"Resolve {len(related)} {severity.lower()} finding(s)",
                            "actions": [item["explanation"]["remediation"] for item in related[:4]],
                            "effort": "Advanced" if severity == "CRITICAL" else "Medium" if severity in {"HIGH", "MEDIUM"} else "Easy",
                            "estimated_time": "1-3 days" if severity == "CRITICAL" else "2-8 hours" if severity in {"HIGH", "MEDIUM"} else "Under 2 hours",
                        }
                    )
            endpoint_urls = sorted({item["url"] for item in endpoints})
            phases = [
                {"name": name, "status": "completed"}
                for name in ("DNS", "SSL", "Headers", "Subdomains", "Crawling", "Technologies", "Analysis", "Advisor", "Report")
            ]
            return {
                "source_name": canonical,
                "content_hash": hashlib.sha256("|".join(endpoint_urls).encode()).hexdigest(),
                "overall_score": overall_risk,
                "overall_level": risk_level,
                "security_score": security_score,
                "grade": grade,
                "findings": findings,
                "finding_count": len(findings),
                "public_exposure_count": sum(item.get("public_accessible", False) for item in findings),
                "mode": "website",
                "scanned_files": len(fetched),
                "scanned_addresses": endpoint_urls,
                "skipped_addresses": sorted(queue - seen)[:20],
                "recommendation": {
                    "priority": risk_level,
                    "summary": f"Grade {grade} ({security_score}/100). Address the highest-risk public findings first, then harden preventive controls.",
                    "actions": [item["explanation"]["remediation"] for item in findings[:5]],
                    "exposed_addresses": list(dict.fromkeys(item["source_address"] for item in findings[:8])),
                },
                "advisor": {
                    "overall_grade": grade,
                    "risk_score": overall_risk,
                    "executive_summary": f"LeakShield assessed {len(endpoint_urls)} public endpoint(s) and identified {len(findings)} prioritized security finding(s).",
                    "technical_summary": "Assessment covered HTTP headers, TLS, DNS, Certificate Transparency subdomains, technology fingerprints, JavaScript, public files, and exposed secret patterns.",
                    "business_impact": findings[0]["explanation"]["business_impact"] if findings else "No material public weakness was identified in the tested surface.",
                    "likelihood": "High" if overall_risk >= 65 else "Medium" if overall_risk >= 35 else "Low",
                    "severity": risk_level,
                    "priority": by_priority[0]["priority"] if by_priority else 4,
                    "estimated_fix_time": by_priority[0]["estimated_time"] if by_priority else "Routine review",
                },
                "roadmap": by_priority,
                "assessment": {
                    "phases": phases,
                    "endpoints": endpoints,
                    "attack_surface": [
                        {
                            "id": item["path"],
                            "url": item["url"],
                            "parent": "/",
                            "type": item["type"],
                            "status": item["status"],
                            "source": item["source"],
                        }
                        for item in endpoints
                    ],
                    "headers": headers,
                    "ssl": ssl_data,
                    "dns": dns_data,
                    "technologies": technologies,
                    "subdomains": subdomains,
                    "javascript": {
                        **javascript,
                        "endpoints": sorted(set(javascript["endpoints"]))[:100],
                        "potential_secrets": sum("Potential" in item["secret_type"] for item in findings),
                    },
                    "threat_intelligence": threat_intel,
                    "robots": next((item["text"] for item in fetched if urlparse(item["url"]).path == "/robots.txt" and item["status"] == 200), None),
                    "sitemap": next((item["text"][:20_000] for item in fetched if "sitemap" in urlparse(item["url"]).path and item["status"] == 200), None),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "disclaimer": "Passive and low-impact checks of publicly accessible content only. Potential exposures require manual verification.",
                },
            }
