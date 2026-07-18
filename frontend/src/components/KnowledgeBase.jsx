import { useDeferredValue, useState } from "react";
import { BookOpen, ExternalLink, Search } from "lucide-react";
import { knowledgeArticles } from "../data/knowledge";

export default function KnowledgeBase() {
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query.toLowerCase());
  const articles = knowledgeArticles.filter((article) =>
    Object.values(article).join(" ").toLowerCase().includes(deferredQuery)
  );

  return (
    <section className="mission-panel knowledge-base" aria-labelledby="knowledge-title">
      <div className="knowledge-head">
        <div>
          <div className="mono-label">LEARN-27 // OFFICIAL SOURCES</div>
          <h2 id="knowledge-title">Interactive Security Knowledge Base</h2>
          <p>Beginner-friendly guidance grounded in OWASP, MITRE, MDN, RFCs, and official documentation.</p>
        </div>
        <label className="field-with-icon knowledge-search">
          <Search className="h-4 w-4" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search headers, SSL, DNS, OWASP..." />
        </label>
      </div>
      <div className="knowledge-grid">
        {articles.map((article) => (
          <details className="knowledge-card" key={article.id}>
            <summary>
              <BookOpen className="h-5 w-5" />
              <span><small>{article.category}</small>{article.title}</span>
            </summary>
            <KnowledgeRow label="Definition" value={article.definition} />
            <KnowledgeRow label="Why it matters" value={article.importance} />
            <KnowledgeRow label="Detection" value={article.detection} />
            <KnowledgeRow label="Common mistakes" value={article.mistakes} />
            <KnowledgeRow label="Mitigation" value={article.mitigation} />
            <div className="reference-row">
              {article.references.map((reference) => (
                <a href={reference.url} target="_blank" rel="noreferrer" key={reference.url}>
                  {reference.title}<ExternalLink className="h-3.5 w-3.5" />
                </a>
              ))}
            </div>
          </details>
        ))}
      </div>
      {!articles.length && <p className="empty-state">No knowledge article matches that search.</p>}
    </section>
  );
}

function KnowledgeRow({ label, value }) {
  return <div className="knowledge-row"><strong>{label}</strong><p>{value}</p></div>;
}
