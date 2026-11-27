import { Bot, ShieldCheck, X } from 'lucide-react';
import { findingTone, verdictBadge } from '../reportUtils';

function checkTone(result) {
  if (result === 'pass') return 'verified';
  if (result === 'fail') return 'rejected';
  if (result === 'not_run') return 'review';
  return 'neutral';
}

export default function PackageDetailView({ row, verifierEnabled, onClose }) {
  if (!row) return null;
  const { dep, reg, risk, rec, ver, statusInfo } = row;
  const vb = ver ? verdictBadge(ver.verdict) : null;

  return (
    <section className="panel" aria-labelledby="pkg-detail-title">
      <div className="panel-header">
        <div>
          <h2 id="pkg-detail-title" className="panel-title">
            Package Inspector: <span className="mono">{row.name}</span>
            <span className={`badge badge-${statusInfo.tone}`}>{statusInfo.label}</span>
          </h2>
          <p className="hint" style={{ margin: '0.25rem 0 0' }}>
            Source: <code className="mono">{dep.source_path}</code>
            {dep.source_line ? ` (line ${dep.source_line})` : ''} · Type: <code>{dep.dependency_type}</code> ·
            Declaration: <code className="mono">{dep.original_declaration}</code>
          </p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          <X size={14} aria-hidden="true" />
          Close
        </button>
      </div>

      <div className="detail-grid">
        {/* Deterministic Evidence & Registry */}
        <div className="subcard">
          <h3>Registry &amp; Evidence (Deterministic — Agent 2)</h3>
          <p style={{ margin: '0 0 0.5rem', fontSize: '0.85rem' }}>
            Status: <code className="mono">{reg?.status || 'unavailable'}</code> ·
            Versions listed: <strong>{reg?.versions?.length ?? 0}</strong> ·
            Latest: <code className="mono">{reg?.latest_version || '—'}</code>
          </p>
          {reg?.error && (
            <div className="alert alert-warn" style={{ marginBottom: '0.6rem' }}>
              <span>Lookup note: {reg.error}</span>
            </div>
          )}
          {reg?.source_url && (
            <p className="hint mono" style={{ wordBreak: 'break-all', margin: '0 0 0.6rem' }}>
              {reg.source_url}
            </p>
          )}
          <ul className="reason-list">
            {(reg?.reasons || []).map((r, i) => (
              <li key={`${r.rule_id}-${i}`} className="reason-item">
                <div className="reason-meta">
                  <span className="mono">{r.rule_id}</span>
                  <span>({r.outcome})</span>
                  {r.evidence_ids?.length > 0 && <span>IDs: {r.evidence_ids.length}</span>}
                </div>
                <div>{r.explanation}</div>
              </li>
            ))}
          </ul>
        </div>

        {/* Deterministic Risk Findings */}
        <div className="subcard">
          <h3>Risk Assessment (Deterministic — Agent 3)</h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginBottom: '0.6rem' }}>
            {(risk?.findings || []).map((f, i) => (
              <span key={`${f.finding}-${i}`} className={`badge badge-${findingTone(f.finding)}`}>
                {f.finding}
              </span>
            ))}
          </div>
          {risk?.baseline_v1 && (
            <p className="hint" style={{ margin: '0 0 0.6rem' }}>
              Frozen v1 baseline (for comparison): level <strong>{risk.baseline_v1.risk_level}</strong>
              {risk.baseline_v1.risk_score !== null ? ` (score ${risk.baseline_v1.risk_score}/100)` : ''}
            </p>
          )}
          <ul className="reason-list">
            {(risk?.reasons || []).map((r, i) => (
              <li key={`${r.rule_id}-${i}`} className="reason-item">
                <div className="reason-meta">
                  <span className="mono">{r.rule_id}</span>
                  <span>({r.outcome})</span>
                </div>
                <div>{r.explanation}</div>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="detail-grid" style={{ marginTop: '0.9rem' }}>
        {/* Agent 4 Recommendation & AI / Rule Reasoning */}
        <div className="subcard">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Bot size={16} color="#38bdf8" aria-hidden="true" />
            Recommendation &amp; Reasoning (Agent 4: {rec?.backend === 'llm' ? rec.model : 'Deterministic Rules'})
          </h3>
          <p style={{ margin: '0 0 0.5rem', fontSize: '0.88rem' }}>
            Action: <strong className="mono">{rec?.action || '—'}</strong>
            {rec?.target && (
              <> → <code className="mono">{rec.target.package.name_normalized}{rec.target.version ? `@${rec.target.version}` : ''}</code></>
            )}
            {' '}· Generation: <code className="mono">{rec?.generation_status}</code>
          </p>

          {rec?.rationale && (
            <div className="alert alert-info" style={{ marginBottom: '0.65rem' }}>
              <div>
                <strong>{rec.backend === 'llm' ? 'AI-Generated Rationale (untrusted until verified):' : 'Rule Rationale:'}</strong>
                <div style={{ marginTop: '0.25rem' }}>{rec.rationale}</div>
              </div>
            </div>
          )}

          {rec?.claims?.length > 0 && (
            <div style={{ marginBottom: '0.65rem' }}>
              <div className="hint" style={{ marginBottom: '0.35rem' }}>Structured Claims Cited:</div>
              <ul className="reason-list">
                {rec.claims.map((c, idx) => (
                  <li key={`${c.type}-${idx}`} className="reason-item">
                    <span className="mono">{c.type}</span> on <code className="mono">{c.subject.name_normalized}</code>
                    {c.object ? ` (${c.object})` : ''} — {c.evidence_ids?.length || 0} evidence ID(s)
                  </li>
                ))}
              </ul>
            </div>
          )}

          <ul className="reason-list">
            {(rec?.reasons || []).map((r, i) => (
              <li key={`${r.rule_id}-${i}`} className="reason-item">
                <div className="reason-meta">
                  <span className="mono">{r.rule_id}</span>
                  <span>({r.outcome})</span>
                </div>
                <div>{r.explanation}</div>
              </li>
            ))}
          </ul>
        </div>

        {/* Agent 5 Independent Deterministic Verification */}
        <div className="subcard">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <ShieldCheck size={16} color="#10b981" aria-hidden="true" />
            Independent Verification Checks (Agent 5 — Deterministic)
          </h3>
          {vb && (
            <p style={{ margin: '0 0 0.6rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span className={`badge badge-${vb.tone}`}>{vb.label}</span>
              {!verifierEnabled && (
                <span className="hint">(Verifier gate toggled off for comparison; Agent 5 audit still shown)</span>
              )}
            </p>
          )}
          <div>
            {(ver?.checks || []).map((chk) => (
              <div key={chk.check} className="check-row">
                <div>
                  <div className="mono" style={{ fontWeight: 600 }}>{chk.check}</div>
                  <div className="hint">{chk.detail}</div>
                </div>
                <span className={`badge badge-${checkTone(chk.result)}`}>{chk.result}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
