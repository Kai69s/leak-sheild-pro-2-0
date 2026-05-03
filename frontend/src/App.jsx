import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Database,
  Filter,
  History,
  KeyRound,
  Loader2,
  RefreshCw,
  Search,
  ShieldCheck,
  TerminalSquare
} from "lucide-react";
import { createScan, getScan, listScans } from "./api";

const defaultInput = `# production deployment leaked into public repo
api_key="prod_live_ci_token_9f2b7c4a6d8e1f0a2b3c4d5e"
db_url=postgres://admin:ProdRootPass2026!@prod-db.internal:5432/payments
password='ProdRootPass2026!'
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.prodtoken.segment`;

const levels = {
  LOW: "text-cyber border-cyber/40 bg-cyber/10",
  MEDIUM: "text-alert border-alert/40 bg-alert/10",
  HIGH: "text-orange-300 border-orange-400/40 bg-orange-400/10",
  CRITICAL: "text-breach border-breach/40 bg-breach/10"
};

function riskColor(level) {
  return {
    LOW: "#20d6b3",
    MEDIUM: "#f59e0b",
    HIGH: "#fb923c",
    CRITICAL: "#fb7185"
  }[level || "LOW"];
}

export default function App() {
  const [content, setContent] = useState(defaultInput);
  const [sourceName, setSourceName] = useState("deployment.env");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [findingFilter, setFindingFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function refreshHistory() {
    const items = await listScans({ q: query, riskLevel: riskFilter });
    setHistory(items);
  }

  useEffect(() => {
    refreshHistory().catch(() => {});
  }, [query, riskFilter]);

  async function scan() {
    setLoading(true);
    setError("");
    try {
      const data = await createScan({
        content,
        source_name: sourceName,
        metadata: { entrypoint: "dashboard", submitted_at: new Date().toISOString() }
      });
      setResult(data);
      await refreshHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadScan(id) {
    setLoading(true);
    try {
      setResult(await getScan(id));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const filteredFindings = useMemo(() => {
    if (!result?.findings) return [];
    const needle = findingFilter.toLowerCase();
    return result.findings.filter((item) =>
      [item.secret_type, item.risk_level, item.rule_id, item.context_snippet].join(" ").toLowerCase().includes(needle)
    );
  }, [result, findingFilter]);

  return (
    <main className="min-h-screen px-4 py-5 sm:px-6 lg:px-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-5">
        <header className="flex flex-col gap-4 border-b border-line pb-5 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <ShieldCheck className="h-8 w-8 text-cyber" />
              <h1 className="text-2xl font-semibold tracking-normal sm:text-3xl">LeakShield Pro</h1>
            </div>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              DevSecOps secret detection with contextual risk scoring, deterministic explanations, Redis caching, and PostgreSQL audit history.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-2 text-center">
            <Metric label="Score" value={result?.overall_score ?? 0} />
            <Metric label="Level" value={result?.overall_level ?? "LOW"} />
            <Metric label="Findings" value={result?.finding_count ?? 0} />
          </div>
        </header>

        <section className="grid gap-5 lg:grid-cols-[1.25fr_0.75fr]">
          <div className="rounded-lg border border-line bg-panel/85">
            <div className="flex flex-col gap-3 border-b border-line p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <TerminalSquare className="h-5 w-5 text-cyber" />
                <h2 className="text-base font-semibold">Scan Input</h2>
              </div>
              <div className="flex gap-2">
                <input
                  className="w-44 rounded-md border border-line bg-ink px-3 py-2 text-sm outline-none focus:border-cyber"
                  value={sourceName}
                  onChange={(event) => setSourceName(event.target.value)}
                  aria-label="Source name"
                />
                <button
                  onClick={scan}
                  disabled={loading}
                  className="inline-flex items-center gap-2 rounded-md bg-cyber px-4 py-2 text-sm font-semibold text-ink disabled:opacity-60"
                  title="Run scan"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                  Scan
                </button>
              </div>
            </div>
            <textarea
              className="h-[430px] w-full resize-none bg-transparent p-4 font-mono text-sm leading-6 text-slate-100 outline-none scrollbar-thin"
              value={content}
              onChange={(event) => setContent(event.target.value)}
              spellCheck={false}
            />
            {error && <div className="border-t border-breach/40 bg-breach/10 p-3 text-sm text-breach">{error}</div>}
          </div>

          <aside className="rounded-lg border border-line bg-panel/85">
            <div className="flex items-center justify-between border-b border-line p-4">
              <div className="flex items-center gap-2">
                <History className="h-5 w-5 text-cyber" />
                <h2 className="text-base font-semibold">Scan History</h2>
              </div>
              <button onClick={refreshHistory} className="rounded-md border border-line p-2 text-slate-300" title="Refresh history">
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
            <div className="grid grid-cols-[1fr_auto] gap-2 border-b border-line p-3">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  className="w-full rounded-md border border-line bg-ink py-2 pl-9 pr-3 text-sm outline-none focus:border-cyber"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search source"
                />
              </div>
              <select
                className="rounded-md border border-line bg-ink px-3 text-sm outline-none focus:border-cyber"
                value={riskFilter}
                onChange={(event) => setRiskFilter(event.target.value)}
                aria-label="Risk filter"
              >
                <option value="">All</option>
                <option>LOW</option>
                <option>MEDIUM</option>
                <option>HIGH</option>
                <option>CRITICAL</option>
              </select>
            </div>
            <div className="max-h-[430px] overflow-auto p-3 scrollbar-thin">
              {history.map((item) => (
                <button
                  key={item.id}
                  onClick={() => loadScan(item.id)}
                  className="mb-2 w-full rounded-lg border border-line bg-ink/70 p-3 text-left hover:border-cyber/60"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="truncate text-sm font-medium">{item.source_name}</span>
                    <span className={`rounded-md border px-2 py-1 text-xs ${levels[item.overall_level]}`}>{item.overall_level}</span>
                  </div>
                  <div className="mt-2 flex justify-between text-xs text-slate-400">
                    <span>{item.finding_count} finding(s)</span>
                    <span>{new Date(item.created_at).toLocaleString()}</span>
                  </div>
                </button>
              ))}
              {!history.length && <p className="p-4 text-sm text-slate-500">No scans match the current filters.</p>}
            </div>
          </aside>
        </section>

        <section className="grid gap-5 lg:grid-cols-[320px_1fr]">
          <RiskPanel result={result} />
          <div className="rounded-lg border border-line bg-panel/85">
            <div className="flex flex-col gap-3 border-b border-line p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <KeyRound className="h-5 w-5 text-cyber" />
                <h2 className="text-base font-semibold">Findings</h2>
              </div>
              <div className="relative">
                <Filter className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  className="w-full rounded-md border border-line bg-ink py-2 pl-9 pr-3 text-sm outline-none focus:border-cyber sm:w-72"
                  value={findingFilter}
                  onChange={(event) => setFindingFilter(event.target.value)}
                  placeholder="Filter findings"
                />
              </div>
            </div>
            <div className="grid gap-3 p-4 md:grid-cols-2">
              {filteredFindings.map((finding) => (
                <FindingCard key={`${finding.rule_id}-${finding.line_number}-${finding.column_start}`} finding={finding} />
              ))}
              {!filteredFindings.length && (
                <div className="col-span-full rounded-lg border border-line bg-ink/70 p-6 text-sm text-slate-400">
                  Run a scan or adjust filters to view categorized detections.
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <div className="text-xs uppercase text-slate-500">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}

function RiskPanel({ result }) {
  const score = result?.overall_score ?? 0;
  const level = result?.overall_level ?? "LOW";
  return (
    <div className="rounded-lg border border-line bg-panel/85 p-5">
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-5 w-5 text-alert" />
        <h2 className="text-base font-semibold">Risk Meter</h2>
      </div>
      <div className="mt-6 flex flex-col items-center">
        <div
          className="risk-meter grid h-48 w-48 place-items-center rounded-full"
          style={{ "--risk-score": score, "--risk-color": riskColor(level) }}
        >
          <div className="grid h-36 w-36 place-items-center rounded-full bg-ink">
            <div className="text-center">
              <div className="text-4xl font-semibold">{score}</div>
              <div className={`mt-2 rounded-md border px-3 py-1 text-xs ${levels[level]}`}>{level}</div>
            </div>
          </div>
        </div>
        <div className="mt-5 grid w-full grid-cols-2 gap-2 text-sm">
          <Metric label="Cache" value={result?.cache_hit ? "HIT" : "MISS"} />
          <Metric label="Hash" value={result?.content_hash ? result.content_hash.slice(0, 8) : "pending"} />
        </div>
      </div>
    </div>
  );
}

function FindingCard({ finding }) {
  return (
    <article className="rounded-lg border border-line bg-ink/70 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">{finding.secret_type}</h3>
          <p className="mt-1 font-mono text-xs text-slate-400">{finding.value_preview}</p>
        </div>
        <span className={`rounded-md border px-2 py-1 text-xs ${levels[finding.risk_level]}`}>{finding.risk_level}</span>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-xs text-slate-400">
        <span>Line {finding.line_number}</span>
        <span>Score {finding.risk_score}</span>
        <span>{finding.severity}</span>
      </div>
      <p className="mt-4 text-sm text-slate-200">{finding.explanation.summary}</p>
      <div className="mt-3 rounded-md border border-line bg-panel/80 p-3">
        <div className="flex items-center gap-2 text-xs uppercase text-slate-500">
          <Database className="h-3.5 w-3.5" />
          Impact
        </div>
        <p className="mt-2 text-sm text-slate-300">{finding.explanation.attacker_impact}</p>
      </div>
      <p className="mt-3 text-xs text-slate-500">{finding.explanation.remediation}</p>
    </article>
  );
}
