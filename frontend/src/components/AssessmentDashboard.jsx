import { useDeferredValue, useState } from "react";
import {
  Activity,
  BarChart3,
  CheckCircle2,
  CircleDot,
  Cloud,
  Code2,
  Download,
  ExternalLink,
  FileSearch,
  GitCompareArrows,
  Globe2,
  Network,
  Radar,
  Search,
  Server,
  ShieldCheck,
  ShieldQuestion,
  Waypoints
} from "lucide-react";

const tabs = ["overview", "surface", "infrastructure", "roadmap"];

export default function AssessmentDashboard({ result }) {
  const [tab, setTab] = useState("overview");
  const [endpointQuery, setEndpointQuery] = useState("");
  const [selectedNode, setSelectedNode] = useState(null);
  const deferredQuery = useDeferredValue(endpointQuery.toLowerCase());
  if (!result?.assessment) return null;

  const { assessment } = result;
  const selectedUrl = safeHttpUrl(selectedNode?.url);
  const endpoints = (assessment.endpoints || []).filter((item) =>
    `${item.url} ${item.type} ${item.status}`.toLowerCase().includes(deferredQuery)
  );
  const aliveSubdomains = (assessment.subdomains || []).filter((item) => item.alive).length;
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((severity) => ({
    severity,
    count: result.findings.filter((finding) => finding.risk_level === severity).length
  }));

  return (
    <section className="assessment-shell" aria-labelledby="assessment-title">
      <div className="assessment-command mission-panel">
        <div>
          <div className="mono-label">ASSESSMENT-360 // PASSIVE PUBLIC INTELLIGENCE</div>
          <h2 id="assessment-title">Cybersecurity Assessment Platform</h2>
          <p>{assessment.disclaimer}</p>
        </div>
        <button className="secondary-command print-command" onClick={() => window.print()} title="Export report as PDF">
          <Download className="h-4 w-4" /> Export PDF
        </button>
      </div>

      <div className="assessment-kpis">
        <Kpi icon={ShieldCheck} label="Security grade" value={result.grade || "-"} detail={`${result.security_score ?? 0}/100`} tone="cyan" />
        <Kpi icon={Waypoints} label="Endpoints" value={assessment.endpoints?.length || 0} detail={`${result.scanned_files || 0} responses inspected`} tone="green" />
        <Kpi icon={Network} label="Subdomains" value={assessment.subdomains?.length || 0} detail={`${aliveSubdomains} responding`} tone="amber" />
        <Kpi icon={Code2} label="Technologies" value={assessment.technologies?.length || 0} detail={`${assessment.javascript?.files?.length || 0} JS assets`} tone="rose" />
      </div>

      <div className="phase-timeline mission-panel" aria-label="Completed scan phases">
        {(assessment.phases || []).map((phase, index) => (
          <div className="phase-node" key={phase.name} style={{ "--phase-index": index }}>
            <CheckCircle2 className="h-4 w-4" />
            <span>{phase.name}</span>
            <small>{phase.status}</small>
          </div>
        ))}
      </div>

      <nav className="assessment-tabs" aria-label="Assessment views">
        {tabs.map((item) => (
          <button type="button" key={item} onClick={() => setTab(item)} className={tab === item ? "assessment-tab-active" : ""}>
            {item}
          </button>
        ))}
      </nav>

      {tab === "overview" && (
        <div className="assessment-view assessment-overview">
          <AdvisorCard advisor={result.advisor} />
          <RiskDistribution severities={severities} score={result.overall_score} />
          <HeaderMatrix headers={assessment.headers || []} />
          <TechnologyDeck technologies={assessment.technologies || []} />
          <Comparison comparison={result.comparison} />
        </div>
      )}

      {tab === "surface" && (
        <div className="assessment-view surface-layout">
          <section className="mission-panel surface-map">
            <SectionTitle icon={Radar} code="MAP-03" title="Interactive Attack Surface" />
            <div className="surface-root"><Globe2 className="h-5 w-5" />{result.source_name}</div>
            {selectedNode && <div className="surface-selection"><strong>{selectedNode.id}</strong><span>{selectedNode.type} · HTTP {selectedNode.status} · {selectedNode.source}</span>{selectedUrl && <a href={selectedUrl} target="_blank" rel="noreferrer">Open endpoint <ExternalLink className="h-3.5 w-3.5" /></a>}</div>}
            <div className="surface-tree">
              {(assessment.attack_surface || []).slice(0, 40).map((node) => (
                <button key={node.url} onClick={() => setSelectedNode(node)} className={selectedNode?.url === node.url ? "surface-node-active" : ""} title={`${node.type} returned ${node.status}`}>
                  <span className={`status-dot status-${statusTone(node.status)}`} />
                  <code>{node.id}</code><small>{node.type} · {node.status}</small>
                </button>
              ))}
            </div>
          </section>
          <section className="mission-panel endpoint-inventory">
            <div className="inventory-head">
              <SectionTitle icon={FileSearch} code="CRAWL-01" title="Discovered Endpoints" />
              <label className="field-with-icon"><Search className="h-4 w-4" /><input value={endpointQuery} onChange={(event) => setEndpointQuery(event.target.value)} placeholder="Filter endpoints" /></label>
            </div>
            <div className="endpoint-table" role="table">
              {endpoints.map((endpoint) => (
                <a href={safeHttpUrl(endpoint.url) || "#"} target="_blank" rel="noreferrer" className="endpoint-row" key={`${endpoint.url}-${endpoint.type}`}>
                  <span className={`status-code status-${statusTone(endpoint.status)}`}>{endpoint.status}</span>
                  <span><strong>{endpoint.path}</strong><small>{endpoint.type} · {endpoint.source}</small></span>
                  <ExternalLink className="h-4 w-4" />
                </a>
              ))}
            </div>
          </section>
          <JavascriptDeck javascript={assessment.javascript || {}} />
        </div>
      )}

      {tab === "infrastructure" && (
        <div className="assessment-view infrastructure-grid">
          <SslCard ssl={assessment.ssl || {}} />
          <DnsCard dns={assessment.dns || {}} />
          <ThreatCard threat={assessment.threat_intelligence || {}} />
          <SubdomainCard subdomains={assessment.subdomains || []} />
        </div>
      )}

      {tab === "roadmap" && (
        <div className="assessment-view roadmap-layout">
          <section className="mission-panel roadmap-panel">
            <SectionTitle icon={BarChart3} code="FIX-28" title="Developer Improvement Roadmap" />
            {(result.roadmap || []).map((item) => (
              <article className="roadmap-step" key={item.severity}>
                <div className="roadmap-priority">P{item.priority}</div>
                <div><span className={`risk-badge risk-${item.severity.toLowerCase()}`}>{item.severity}</span><h3>{item.title}</h3><p>{item.actions?.[0]}</p></div>
                <div className="roadmap-effort"><strong>{item.effort}</strong><small>{item.estimated_time}</small></div>
              </article>
            ))}
            {!result.roadmap?.length && <p className="empty-state">No prioritized remediation work was generated.</p>}
          </section>
        </div>
      )}
    </section>
  );
}

function Kpi({ icon: Icon, label, value, detail, tone }) {
  return <article className={`assessment-kpi kpi-${tone}`}><Icon className="h-5 w-5" /><div><small>{label}</small><strong>{value}</strong><span>{detail}</span></div></article>;
}

function SectionTitle({ icon: Icon, code, title }) {
  return <div className="section-title"><Icon className="h-5 w-5" /><div><small>{code}</small><h3>{title}</h3></div></div>;
}

function AdvisorCard({ advisor }) {
  if (!advisor) return null;
  return (
    <section className="mission-panel advisor-card">
      <SectionTitle icon={ShieldQuestion} code="ADVISOR-08" title="Open Security Advisor" />
      <p className="advisor-lead">{advisor.executive_summary}</p>
      <div className="advisor-grid">
        <div><small>Technical summary</small><p>{advisor.technical_summary}</p></div>
        <div><small>Business impact</small><p>{advisor.business_impact}</p></div>
      </div>
      <div className="advisor-flags"><span>Likelihood <strong>{advisor.likelihood}</strong></span><span>Severity <strong>{advisor.severity}</strong></span><span>Fix window <strong>{advisor.estimated_fix_time}</strong></span></div>
    </section>
  );
}

function RiskDistribution({ severities, score }) {
  const total = Math.max(1, severities.reduce((sum, item) => sum + item.count, 0));
  return (
    <section className="mission-panel risk-distribution">
      <SectionTitle icon={Activity} code="RISK-09" title="Risk Distribution" />
      <div className="risk-chart-wrap">
        <div className="risk-donut" style={{ "--score": `${Math.min(100, score || 0) * 3.6}deg` }}><strong>{score || 0}</strong><small>risk</small></div>
        <div className="risk-bars">
          {severities.map((item) => <div key={item.severity}><span>{item.severity}</span><i><b style={{ width: `${(item.count / total) * 100}%` }} /></i><strong>{item.count}</strong></div>)}
        </div>
      </div>
    </section>
  );
}

function HeaderMatrix({ headers }) {
  return (
    <section className="mission-panel header-matrix">
      <SectionTitle icon={ShieldCheck} code="HEAD-04" title="Security Headers" />
      <div className="header-list">
        {headers.map((header) => <div key={header.name} className={header.present ? "header-present" : "header-missing"}><CircleDot className="h-4 w-4" /><span><strong>{header.name}</strong><small>{header.value || header.recommendation}</small></span><b>{header.present ? "PRESENT" : header.risk}</b></div>)}
      </div>
    </section>
  );
}

function TechnologyDeck({ technologies }) {
  return <section className="mission-panel technology-deck"><SectionTitle icon={Code2} code="TECH-07" title="Technology Fingerprints" /><div>{technologies.map((item) => <span key={item.name}>{item.name}<small>{item.confidence}</small></span>)}</div>{!technologies.length && <p className="empty-state">No reliable technology signature was exposed.</p>}</section>;
}

function Comparison({ comparison }) {
  return <section className="mission-panel comparison-card"><SectionTitle icon={GitCompareArrows} code="DIFF-13" title="Previous Scan Comparison" />{comparison?.has_previous ? <><div className="comparison-score"><strong>{comparison.risk_change > 0 ? "+" : ""}{comparison.risk_change}</strong><span>risk change from {comparison.previous_score}</span></div><p>{comparison.new_findings.length} new · {comparison.fixed_findings.length} fixed</p></> : <p className="empty-state">This is the baseline scan. Re-scan the same target to track new and fixed findings.</p>}</section>;
}

function SslCard({ ssl }) {
  return <section className="mission-panel infrastructure-card"><SectionTitle icon={ShieldCheck} code="TLS-05" title="SSL / TLS" /><DataRow label="Status" value={ssl.valid ? "Valid" : "Needs attention"} /><DataRow label="Issuer" value={ssl.issuer} /><DataRow label="TLS" value={ssl.tls_version} /><DataRow label="Cipher" value={ssl.cipher} /><DataRow label="Expires" value={ssl.expires_at} /><DataRow label="Days left" value={ssl.days_remaining} /></section>;
}

function DnsCard({ dns }) {
  const records = dns.records || {};
  return <section className="mission-panel infrastructure-card dns-card"><SectionTitle icon={Network} code="DNS-06" title="DNS Posture" /><DataRow label="DNSSEC" value={dns.dnssec ? "Detected" : "Not detected"} />{Object.entries(records).map(([type, values]) => <DataRow key={type} label={type} value={values?.length ? values.slice(0, 2).join(" · ") : "Not found"} />)}</section>;
}

function ThreatCard({ threat }) {
  return <section className="mission-panel infrastructure-card"><SectionTitle icon={Cloud} code="INTEL-17" title="Threat Intelligence" /><DataRow label="IP" value={threat.ip} /><DataRow label="Reverse DNS" value={threat.reverse_dns} /><DataRow label="Network" value={threat.asn_name || threat.handle} /><DataRow label="Country" value={threat.country} /><DataRow label="Range" value={threat.network} /></section>;
}

function SubdomainCard({ subdomains }) {
  return <section className="mission-panel infrastructure-card subdomain-card"><SectionTitle icon={Server} code="SUB-02" title="Subdomain Enumeration" /><div className="subdomain-list">{subdomains.slice(0, 40).map((item) => <div key={item.hostname}><span className={`status-dot ${item.alive ? "status-green" : "status-red"}`} /><strong>{item.hostname}</strong><small>{item.status || "dead"} · {item.technology || "unknown"} · {item.ssl ? "TLS" : "no TLS"}</small></div>)}</div></section>;
}

function JavascriptDeck({ javascript }) {
  return <section className="mission-panel javascript-deck"><SectionTitle icon={Code2} code="JS-19" title="JavaScript Intelligence" /><div className="js-stats"><span><strong>{javascript.files?.length || 0}</strong> files</span><span><strong>{javascript.endpoints?.length || 0}</strong> endpoints</span><span><strong>{javascript.source_maps?.length || 0}</strong> source maps</span><span><strong>{javascript.potential_secrets || 0}</strong> potential secrets</span></div><div className="address-deck">{javascript.endpoints?.slice(0, 24).map((endpoint) => <code key={endpoint}>{endpoint}</code>)}</div></section>;
}

function DataRow({ label, value }) {
  return <div className="data-row"><span>{label}</span><strong>{value ?? "Unavailable"}</strong></div>;
}

function statusTone(status) {
  if (status >= 200 && status < 300) return "green";
  if (status >= 300 && status < 400) return "amber";
  return "red";
}

function safeHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return ["http:", "https:"].includes(parsed.protocol) ? parsed.toString() : "";
  } catch {
    return "";
  }
}
