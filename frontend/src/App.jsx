import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Cpu,
  Database,
  FileCode2,
  Filter,
  Fingerprint,
  FolderOpen,
  Gauge,
  Globe2,
  History,
  KeyRound,
  Link2,
  Loader2,
  LockKeyhole,
  RefreshCw,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  UploadCloud,
  Zap
} from "lucide-react";
import { createScan, getScan, listScans } from "./api";

const defaultInput = `# production deployment leaked into public repo
api_key="prod_live_ci_token_9f2b7c4a6d8e1f0a2b3c4d5e"
db_url=postgres://admin:ProdRootPass2026!@prod-db.internal:5432/payments
password='ProdRootPass2026!'
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.prodtoken.segment`;

const levels = {
  LOW: "text-cyan-200 border-cyan-300/40 bg-cyan-300/10",
  MEDIUM: "text-amber-200 border-amber-300/40 bg-amber-300/10",
  HIGH: "text-orange-200 border-orange-300/40 bg-orange-300/10",
  CRITICAL: "text-rose-200 border-rose-300/50 bg-rose-400/10"
};

const orbitSatellites = Array.from({ length: 26 }, (_, index) => index);
const orbitMeridians = Array.from({ length: 14 }, (_, index) => index);
const orbitLatitudes = Array.from({ length: 9 }, (_, index) => index);

function riskColor(level) {
  return {
    LOW: "#6ee7f9",
    MEDIUM: "#fbbf24",
    HIGH: "#fb923c",
    CRITICAL: "#fb7185"
  }[level || "LOW"];
}

export default function App() {
  const [content, setContent] = useState(defaultInput);
  const [sourceName, setSourceName] = useState("deployment.env");
  const [scanMode, setScanMode] = useState("text");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [projectFiles, setProjectFiles] = useState([]);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [findingFilter, setFindingFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const showTextMode = useCallback(() => setScanMode("text"), []);
  const showFolderMode = useCallback(() => setScanMode("project-folder"), []);
  const showWebsiteMode = useCallback(() => setScanMode("website"), []);
  const scanStateRef = useRef({ content, sourceName, scanMode, websiteUrl, projectFiles });

  useEffect(() => {
    scanStateRef.current = { content, sourceName, scanMode, websiteUrl, projectFiles };
  }, [content, sourceName, scanMode, websiteUrl, projectFiles]);

  const refreshHistory = useCallback(async () => {
    const items = await listScans({ q: query, riskLevel: riskFilter });
    setHistory(items);
  }, [query, riskFilter]);

  useEffect(() => {
    refreshHistory().catch(() => {});
  }, [refreshHistory]);

  const scan = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { content, sourceName, scanMode, websiteUrl, projectFiles } = scanStateRef.current;
      const payload =
        scanMode === "website"
          ? {
              mode: "website",
              website_url: websiteUrl,
              source_name: websiteUrl || "website-scan",
              metadata: { entrypoint: "website-url", submitted_at: new Date().toISOString() }
            }
          : scanMode === "project-folder"
            ? {
                mode: "project-folder",
                files: projectFiles,
                source_name: sourceName || "uploaded-project",
                metadata: { entrypoint: "folder-upload", submitted_at: new Date().toISOString() }
              }
            : {
                mode: "text",
                content,
                source_name: sourceName,
                metadata: { entrypoint: "dashboard", submitted_at: new Date().toISOString() }
              };
      const data = await createScan(payload);
      setResult(data);
      await refreshHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [refreshHistory]);

  const handleFolderUpload = useCallback(async (event) => {
    const files = Array.from(event.target.files || []);
    setError("");
    const readableFiles = files
      .filter((file) => !file.name.match(/\.(png|jpg|jpeg|gif|webp|ico|pdf|zip|exe|dll|woff2?|ttf|mp4|mp3)$/i))
      .slice(0, 80);
    const loaded = await Promise.all(
      readableFiles.map(async (file) => ({
        path: file.webkitRelativePath || file.name,
        size: file.size,
        content: await file.text()
      }))
    );
    setProjectFiles(loaded);
    setSourceName(files[0]?.webkitRelativePath?.split("/")[0] || "uploaded-project");
    setContent(
      loaded
        .slice(0, 12)
        .map((file) => `// ${file.path}\n${file.content.slice(0, 700)}`)
        .join("\n\n")
    );
  }, []);

  const loadScan = useCallback(async (id) => {
    setLoading(true);
    try {
      setResult(await getScan(id));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const filteredFindings = useMemo(() => {
    if (!result?.findings) return [];
    const needle = findingFilter.toLowerCase();
    return result.findings.filter((item) =>
      [item.secret_type, item.risk_level, item.rule_id, item.context_snippet, item.file_path, item.source_address]
        .join(" ")
        .toLowerCase()
        .includes(needle)
    );
  }, [result, findingFilter]);

  return (
    <main className="mission-shell min-h-screen overflow-hidden text-slate-100">
      <div className="scanline" />
      <div className="mx-auto flex max-w-[1500px] flex-col gap-6 px-4 py-5 sm:px-6 lg:px-10">
        <MemoMissionHeader loading={loading} result={result} />
        <MemoHeroSection loading={loading} result={result} onScan={scan} onRefreshHistory={refreshHistory} />
        <section className="ops-grid">
          <MemoCommandPanel
            content={content}
            error={error}
            handleFolderUpload={handleFolderUpload}
            projectFiles={projectFiles}
            scanMode={scanMode}
            setContent={setContent}
            setSourceName={setSourceName}
            setWebsiteUrl={setWebsiteUrl}
            showFolderMode={showFolderMode}
            showTextMode={showTextMode}
            showWebsiteMode={showWebsiteMode}
            sourceName={sourceName}
            websiteUrl={websiteUrl}
          />
          <MemoHistoryPanel
            history={history}
            loadScan={loadScan}
            query={query}
            riskFilter={riskFilter}
            setQuery={setQuery}
            setRiskFilter={setRiskFilter}
          />
        </section>
        <MemoAnalysisSection
          filteredFindings={filteredFindings}
          findingFilter={findingFilter}
          result={result}
          setFindingFilter={setFindingFilter}
        />
      </div>
    </main>
  );
}

function MissionHeader({ loading, result }) {
  return (
    <header className="mission-header">
      <div className="flex items-center gap-3">
        <div className="sigil">
          <Fingerprint className="h-5 w-5" />
        </div>
        <div>
          <div className="mono-label">LEAKSHIELD PRO // PUBLIC EXPOSURE AI</div>
          <h1 className="text-xl font-semibold tracking-normal text-white sm:text-2xl">Orbital Secret Defense Console</h1>
        </div>
      </div>
      <div className="hidden items-center gap-3 lg:flex">
        <MemoTelemetryPill icon={Activity} label="Engine" value={loading ? "SCANNING" : "ARMED"} tone="green" />
        <MemoTelemetryPill icon={ShieldAlert} label="Risk" value={result?.overall_level ?? "STANDBY"} tone="red" />
      </div>
    </header>
  );
}

const MemoMissionHeader = memo(MissionHeader);

function HeroSection({ loading, result, onScan, onRefreshHistory }) {
  return (
    <section className="hero-grid">
      <div className="hero-copy">
        <div className="classification">
          <LockKeyhole className="h-4 w-4" />
          CLASSIFIED-GRADE DEVSECOPS ANALYSIS
        </div>
        <h2 className="hero-title">
          Expose every leak
          <span> before launch.</span>
        </h2>
        <p className="hero-subtitle">
          Upload a project, inspect a public website, or paste sensitive code. LeakShield maps exposed secrets to exact
          file and URL addresses, scores operational risk, and returns a mission-ready remediation plan.
        </p>
        <div className="mission-actions">
          <button onClick={onScan} disabled={loading} className="primary-command" title="Run scan">
            {loading ? <Loader2 className="h-5 w-5 animate-spin" /> : <ScanLine className="h-5 w-5" />}
            Initiate Exposure Sweep
          </button>
          <button onClick={onRefreshHistory} className="secondary-command" title="Refresh history">
            <RefreshCw className="h-5 w-5" />
            Sync Console
          </button>
        </div>
      </div>

      <div className="orbit-stage">
        <MemoOrbitSphere result={result} loading={loading} />
        <div className="floating-card floating-card-a">
          <div className="mono-label text-cyan-200">ACTIVE SCAN</div>
          <strong>{result?.source_name ?? "No target locked"}</strong>
          <span>{result ? `${result.scanned_files ?? 1} file/address unit(s) inspected` : "Awaiting scan vector"}</span>
        </div>
        <div className="floating-card floating-card-b">
          <div className="mono-label text-rose-200">VERDICT</div>
          <strong>{result ? `${result.overall_score}/100 ${result.overall_level}` : "0/100 STANDBY"}</strong>
          <span>{result?.finding_count ?? 0} exposure signal(s) isolated</span>
        </div>
      </div>
    </section>
  );
}

const MemoHeroSection = memo(HeroSection);

function CommandPanel({
  content,
  error,
  handleFolderUpload,
  projectFiles,
  scanMode,
  setContent,
  setSourceName,
  setWebsiteUrl,
  showFolderMode,
  showTextMode,
  showWebsiteMode,
  sourceName,
  websiteUrl
}) {
  return (
    <div className="mission-panel command-panel">
      <MemoPanelHeader icon={Cpu} title="Threat Acquisition" code="INPUT-01" />
      <div className="mode-rail">
        <MemoModeButton active={scanMode === "text"} onClick={showTextMode} icon={TerminalSquare} label="Text" />
        <MemoModeButton active={scanMode === "project-folder"} onClick={showFolderMode} icon={FolderOpen} label="Folder" />
        <MemoModeButton active={scanMode === "website"} onClick={showWebsiteMode} icon={Globe2} label="Website" />
      </div>

      <div className="target-row">
        <label className="field-block">
          <span>Target Name</span>
          <input value={sourceName} onChange={(event) => setSourceName(event.target.value)} aria-label="Source name" />
        </label>
        {scanMode === "project-folder" && (
          <label className="upload-command">
            <UploadCloud className="h-5 w-5" />
            Upload Project Folder
            <input type="file" className="hidden" multiple webkitdirectory="" directory="" onChange={handleFolderUpload} />
            <small>{projectFiles.length ? `${projectFiles.length} files loaded` : "Select a source tree"}</small>
          </label>
        )}
        {scanMode === "website" && (
          <label className="field-block grow">
            <span>Public Website Link</span>
            <div className="field-with-icon">
              <Link2 className="h-4 w-4" />
              <input
                value={websiteUrl}
                onChange={(event) => setWebsiteUrl(event.target.value)}
                placeholder="https://example.com"
                aria-label="Website URL"
              />
            </div>
          </label>
        )}
      </div>

      <div className="editor-shell">
        <div className="editor-toolbar">
          <span>{scanMode === "website" ? "REMOTE ASSET FETCH" : scanMode === "project-folder" ? "PROJECT PREVIEW" : "RAW INPUT"}</span>
          <span>{scanMode === "project-folder" ? `${projectFiles.length} files` : `${content.length} chars`}</span>
        </div>
        <textarea
          value={content}
          onChange={(event) => setContent(event.target.value)}
          readOnly={scanMode === "website"}
          spellCheck={false}
          placeholder={scanMode === "website" ? "Enter a website URL above. LeakShield will fetch public HTML and linked assets." : ""}
        />
      </div>
      {error && <div className="error-band">{error}</div>}
    </div>
  );
}

const MemoCommandPanel = memo(CommandPanel);

function HistoryPanel({ history, loadScan, query, riskFilter, setQuery, setRiskFilter }) {
  return (
    <aside className="mission-panel">
      <MemoPanelHeader icon={History} title="Mission Archive" code="HIST-07" />
      <div className="history-filters">
        <div className="field-with-icon">
          <Search className="h-4 w-4" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search source" />
        </div>
        <select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)} aria-label="Risk filter">
          <option value="">All</option>
          <option>LOW</option>
          <option>MEDIUM</option>
          <option>HIGH</option>
          <option>CRITICAL</option>
        </select>
      </div>
      <div className="history-list">
        {history.map((item) => (
          <button key={item.id} onClick={() => loadScan(item.id)} className="history-item">
            <span className="truncate text-sm font-semibold text-white">{item.source_name}</span>
            <span className={`risk-badge ${levels[item.overall_level]}`}>{item.overall_level}</span>
            <small>{item.finding_count} finding(s)</small>
            <small>{new Date(item.created_at).toLocaleString()}</small>
          </button>
        ))}
        {!history.length && <p className="empty-state">No archived scans match the current filters.</p>}
      </div>
    </aside>
  );
}

const MemoHistoryPanel = memo(HistoryPanel);

function AnalysisSection({ filteredFindings, findingFilter, result, setFindingFilter }) {
  return (
    <section className="analysis-grid">
      <MemoRiskPanel result={result} />
      <div className="mission-panel">
        <div className="flex flex-col gap-3 border-b border-white/10 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <MemoPanelHeader icon={KeyRound} title="Exposure Findings" code="INTEL-22" compact />
          <div className="field-with-icon max-w-sm">
            <Filter className="h-4 w-4" />
            <input value={findingFilter} onChange={(event) => setFindingFilter(event.target.value)} placeholder="Filter findings" />
          </div>
        </div>
        <div className="finding-grid">
          {result?.recommendation && <MemoRecommendationCard recommendation={result.recommendation} />}
          {filteredFindings.map((finding) => (
            <MemoFindingCard key={`${finding.rule_id}-${finding.line_number}-${finding.column_start}-${finding.file_path || finding.source_address}`} finding={finding} />
          ))}
          {!filteredFindings.length && <div className="empty-state col-span-full">Run a scan to populate the forensic evidence deck.</div>}
        </div>
      </div>
    </section>
  );
}

const MemoAnalysisSection = memo(AnalysisSection);

function PanelHeader({ icon: Icon, title, code, compact = false }) {
  return (
    <div className={`panel-header ${compact ? "mb-0" : ""}`}>
      <div className="panel-icon">
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <div className="mono-label">{code}</div>
        <h3>{title}</h3>
      </div>
    </div>
  );
}

function TelemetryPill({ icon: Icon, label, value, tone }) {
  return (
    <div className={`telemetry-pill telemetry-${tone}`}>
      <Icon className="h-4 w-4" />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

const MemoPanelHeader = memo(PanelHeader);
const MemoTelemetryPill = memo(TelemetryPill);

function ModeButton({ active, onClick, icon: Icon, label }) {
  return (
    <button type="button" onClick={onClick} className={`mode-button ${active ? "mode-button-active" : ""}`}>
      <Icon className="h-4 w-4" />
      {label}
    </button>
  );
}

const MemoModeButton = memo(ModeButton);

function OrbitSphere({ result, loading }) {
  const level = result?.overall_level ?? "LOW";
  const color = riskColor(level);
  return (
    <div className={`orbit-sphere ${loading ? "orbit-sphere-hot" : ""}`} style={{ "--orbit-color": color }}>
      <div className="deep-halo" />
      <div className="sphere-core" />
      <div className="wireframe-shell">
        {orbitMeridians.map((item) => (
          <span key={`m-${item}`} className="meridian" style={{ "--i": item }} />
        ))}
        {orbitLatitudes.map((item) => (
          <span key={`l-${item}`} className="latitude" style={{ "--i": item }} />
        ))}
        <span className="mesh-layer mesh-layer-a" />
        <span className="mesh-layer mesh-layer-b" />
        <span className="mesh-layer mesh-layer-c" />
      </div>
      <div className="orbit-ring orbit-ring-a" />
      <div className="orbit-ring orbit-ring-b" />
      <div className="orbit-ring orbit-ring-c" />
      <div className="orbit-ring orbit-ring-d" />
      <div className="radar-sweep" />
      <div className="equator-beam" />
      <div className="core-aperture" />
      <div className="satellite-field">
        {orbitSatellites.map((item) => (
          <span key={item} className="satellite-dot" style={{ "--i": item }} />
        ))}
      </div>
    </div>
  );
}

const MemoOrbitSphere = memo(OrbitSphere);

function RiskPanel({ result }) {
  const score = result?.overall_score ?? 0;
  const level = result?.overall_level ?? "LOW";
  return (
    <div className="mission-panel risk-panel">
      <PanelHeader icon={Gauge} title="Risk Reactor" code="CORE-03" />
      <div className="risk-reactor" style={{ "--risk-score": score, "--risk-color": riskColor(level) }}>
        <div className="risk-inner">
          <span>{score}</span>
          <strong>{level}</strong>
        </div>
      </div>
      <div className="metric-grid">
        <MemoMetric label="Findings" value={result?.finding_count ?? 0} />
        <MemoMetric label="Public" value={result?.public_exposure_count ?? 0} />
        <MemoMetric label="Files" value={result?.scanned_files ?? 0} />
        <MemoMetric label="URLs" value={result?.scanned_addresses?.length ?? 0} />
        <MemoMetric label="Hash" value={result?.content_hash ? result.content_hash.slice(0, 8) : "pending"} />
      </div>
    </div>
  );
}

const MemoRiskPanel = memo(RiskPanel);

function Metric({ label, value }) {
  return (
    <div className="metric-tile">
      <small>{label}</small>
      <strong>{value}</strong>
    </div>
  );
}

const MemoMetric = memo(Metric);

function RecommendationCard({ recommendation }) {
  return (
    <article className="recommendation-card">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="mono-label text-cyan-200">REMEDIATION VECTOR</div>
          <h3>Recommended Fix Plan</h3>
        </div>
        <span className={`risk-badge ${levels[recommendation.priority] || levels.LOW}`}>{recommendation.priority}</span>
      </div>
      <p>{recommendation.summary}</p>
      {recommendation.exposed_addresses?.length > 0 && (
        <div className="address-deck">
          {recommendation.exposed_addresses.map((address) => (
            <code key={address}>{address}</code>
          ))}
        </div>
      )}
      <div className="action-stack">
        {recommendation.actions.map((action) => (
          <div key={action} className="action-row">
            <Zap className="h-4 w-4" />
            <span>{action}</span>
          </div>
        ))}
      </div>
    </article>
  );
}

const MemoRecommendationCard = memo(RecommendationCard);

function FindingCard({ finding }) {
  const address = finding.file_path || finding.source_address || finding.source_name;
  return (
    <article className="finding-card">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="mono-label">{finding.rule_id}</div>
          <h3>{finding.secret_type}</h3>
          <p className="font-mono text-xs text-slate-400">{finding.value_preview}</p>
        </div>
        <span className={`risk-badge ${levels[finding.risk_level]}`}>{finding.risk_level}</span>
      </div>
      <div className="finding-metrics">
        <span>Line {finding.line_number}</span>
        <span>Score {finding.risk_score}</span>
        <span>{finding.confidence ? `${Math.round(finding.confidence * 100)}% conf` : finding.severity}</span>
      </div>
      {address && (
        <div className="address-panel">
          <div className="flex items-center gap-2 text-xs uppercase text-slate-500">
            <FileCode2 className="h-3.5 w-3.5" />
            Specific address
          </div>
          <code>
            {address}:{finding.line_number}:{finding.column_start}
          </code>
          {finding.public_accessible && <span>Publicly accessible surface confirmed</span>}
        </div>
      )}
      <p className="mt-4 text-sm text-slate-200">{finding.explanation.summary}</p>
      <div className="impact-box">
        <div className="flex items-center gap-2 text-xs uppercase text-slate-500">
          <Database className="h-3.5 w-3.5" />
          Impact
        </div>
        <p>{finding.explanation.attacker_impact}</p>
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-500">{finding.explanation.remediation}</p>
    </article>
  );
}

const MemoFindingCard = memo(FindingCard);
