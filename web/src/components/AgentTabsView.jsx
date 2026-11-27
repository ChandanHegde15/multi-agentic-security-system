import { useState } from 'react';
import { Download, FileCheck2 } from 'lucide-react';
import { getExportUrl } from '../api';
import { verdictBadge } from '../reportUtils';
import PackageResultsTable from './PackageResultsTable';

const TABS = [
  { id: 'overview', label: 'Results Overview' },
  { id: 'agent1', label: 'Agent 1: Extraction' },
  { id: 'agent2', label: 'Agent 2: Registry' },
  { id: 'agent3', label: 'Agent 3: Risk' },
  { id: 'agent4', label: 'Agent 4: Recommend' },
  { id: 'agent5', label: 'Agent 5: Verify' },
  { id: 'report', label: 'Final Report' },
];

export default function AgentTabsView({ scan, rows, selectedId, onSelect }) {
  const [activeTab, setActiveTab] = useState('overview');
  const report = scan?.report;
  if (!report) return null;

  const summary = report.summary || {};
  const allFailures = [
    ...(report.extraction?.failures || []),
    ...(report.registry?.failures || []),
    ...(report.risk?.failures || []),
    ...(report.recommendations?.failures || []),
    ...(report.verification?.failures || []),
  ];

  return (
    <section className="panel" aria-label="Multi-agent inspection tabs">
      <div className="panel-header">
        <h2 className="panel-title">
          <FileCheck2 size={18} aria-hidden="true" />
          Analysis Results &amp; Agent Outputs
        </h2>
        <a
          className="btn btn-secondary"
          href={getExportUrl(scan.scan_id)}
          download={`security-report-${scan.scan_id}.json`}
        >
          <Download size={15} aria-hidden="true" />
          Export JSON Report
        </a>
      </div>

      <div className="tablist" role="tablist" aria-label="Agent outputs and report views">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            className="tab-btn"
            aria-selected={activeTab === t.id}
            onClick={() => setActiveTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <PackageResultsTable rows={rows} selectedId={selectedId} onSelect={onSelect} />
      )}

      {activeTab === 'agent1' && (
        <div>
          <p className="hint">
            Stage version: <code className="mono">{report.extraction?.stage_version}</code> ·
            Sources parsed: <strong>{report.extraction?.sources?.length || 0}</strong> ·
            Dependencies extracted: <strong>{report.extraction?.dependencies?.length || 0}</strong>
          </p>
          <ul className="reason-list">
            {(report.extraction?.dependencies || []).map((dep) => (
              <li key={dep.dependency_id} className="reason-item">
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <strong>
                    <code className="mono">{dep.package?.name_normalized || dep.original_declaration}</code> ({dep.ecosystem || 'unresolved'})
                  </strong>
                  <span className="badge badge-neutral">{dep.extraction_status}</span>
                </div>
                <div className="hint">
                  Source: <code className="mono">{dep.source_path}</code> · Constraint: <code className="mono">{dep.version_constraint_raw || 'none'}</code>
                </div>
                {dep.reasons?.map((r, i) => (
                  <div key={i} style={{ marginTop: '0.3rem' }}>
                    <code className="mono" style={{ color: 'var(--accent-cyan)' }}>{r.rule_id}</code>: {r.explanation}
                  </div>
                ))}
              </li>
            ))}
          </ul>
        </div>
      )}

      {activeTab === 'agent2' && (
        <div>
          <p className="hint">
            Registry mode: <code className="mono">{report.registry?.registry_mode}</code> ·
            Evidence records indexed: <strong>{report.registry?.evidence_store?.records_indexed ?? 0}</strong>
          </p>
          <ul className="reason-list">
            {rows.map((row) => (
              <li key={row.dependency_id} className="reason-item">
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
                  <strong className="mono">{row.name}</strong>
                  <span className="badge badge-neutral">{row.reg?.status}</span>
                </div>
                {row.reg?.reasons?.map((r, i) => (
                  <div key={i} style={{ marginTop: '0.3rem' }}>
                    <code className="mono" style={{ color: 'var(--accent-cyan)' }}>{r.rule_id}</code>: {r.explanation}
                  </div>
                ))}
              </li>
            ))}
          </ul>
        </div>
      )}

      {activeTab === 'agent3' && (
        <div>
          <p className="hint">
            Stage version: <code className="mono">{report.risk?.stage_version}</code> ·
            Side-by-side v2 family findings and frozen v1 baseline score.
          </p>
          <ul className="reason-list">
            {rows.map((row) => (
              <li key={row.dependency_id} className="reason-item">
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <strong className="mono">{row.name}</strong>
                  <span className="hint">
                    v1 baseline: <strong>{row.risk?.baseline_v1?.risk_level || 'none'}</strong>
                    {row.risk?.baseline_v1?.risk_score !== null && row.risk?.baseline_v1?.risk_score !== undefined
                      ? ` (${row.risk.baseline_v1.risk_score})`
                      : ''}
                  </span>
                </div>
                {row.risk?.reasons?.map((r, i) => (
                  <div key={i} style={{ marginTop: '0.3rem' }}>
                    <code className="mono" style={{ color: 'var(--accent-cyan)' }}>{r.rule_id}</code>: {r.explanation}
                  </div>
                ))}
              </li>
            ))}
          </ul>
        </div>
      )}

      {activeTab === 'agent4' && (
        <div>
          <p className="hint">
            Stage version: <code className="mono">{report.recommendations?.stage_version}</code> ·
            Recommender variant: <code className="mono">{scan.variant}</code>
          </p>
          <ul className="reason-list">
            {rows.map((row) => (
              <li key={row.dependency_id} className="reason-item">
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <strong className="mono">
                    {row.name} → {row.rec?.action}
                    {row.rec?.target ? ` (${row.rec.target.package.name_normalized}${row.rec.target.version ? `@${row.rec.target.version}` : ''})` : ''}
                  </strong>
                  <span className="badge badge-neutral">{row.rec?.backend} / {row.rec?.generation_status}</span>
                </div>
                {row.rec?.rationale && (
                  <div style={{ marginTop: '0.35rem', color: 'var(--text-primary)' }}>
                    <strong>Rationale:</strong> {row.rec.rationale}
                  </div>
                )}
                {row.rec?.reasons?.map((r, i) => (
                  <div key={i} style={{ marginTop: '0.3rem' }}>
                    <code className="mono" style={{ color: 'var(--accent-cyan)' }}>{r.rule_id}</code>: {r.explanation}
                  </div>
                ))}
              </li>
            ))}
          </ul>
        </div>
      )}

      {activeTab === 'agent5' && (
        <div>
          <p className="hint">
            Stage version: <code className="mono">{report.verification?.stage_version}</code> ·
            Independent 10-check deterministic verifier (no shared code with Agent 4).
          </p>
          <ul className="reason-list">
            {rows.map((row) => {
              const vb = row.ver ? verdictBadge(row.ver.verdict) : null;
              return (
                <li key={row.dependency_id} className="reason-item">
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <strong className="mono">{row.name}</strong>
                    {vb && <span className={`badge badge-${vb.tone}`}>{vb.label}</span>}
                  </div>
                  {row.ver?.reasons?.slice(-2).map((r, i) => (
                    <div key={i} style={{ marginTop: '0.3rem' }}>
                      <code className="mono" style={{ color: 'var(--accent-cyan)' }}>{r.rule_id}</code>: {r.explanation}
                    </div>
                  ))}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {activeTab === 'report' && (
        <div className="detail-grid">
          <div className="subcard">
            <h3>Executive Summary</h3>
            <ul className="reason-list">
              <li className="reason-item">
                Dependencies Scanned: <strong>{summary.total_dependencies ?? 0}</strong>
              </li>
              <li className="reason-item">
                Ecosystems: <code className="mono">{JSON.stringify(summary.by_ecosystem || {})}</code>
              </li>
              <li className="reason-item">
                Registry Statuses: <code className="mono">{JSON.stringify(summary.registry_status_counts || {})}</code>
              </li>
              <li className="reason-item">
                Risk Findings: <code className="mono">{JSON.stringify(summary.finding_counts || {})}</code>
              </li>
              <li className="reason-item">
                Recommended Actions: <code className="mono">{JSON.stringify(summary.action_counts || {})}</code>
              </li>
              <li className="reason-item">
                Agent 5 Verdicts: <code className="mono">{JSON.stringify(summary.verdict_counts || {})}</code>
              </li>
            </ul>
          </div>

          <div className="subcard">
            <h3>Unresolved Issues &amp; Stage Failures ({allFailures.length})</h3>
            {allFailures.length === 0 ? (
              <p className="hint">All pipeline stages completed with zero stage failures.</p>
            ) : (
              <ul className="reason-list">
                {allFailures.map((f, i) => (
                  <li key={`${f.code}-${i}`} className="reason-item">
                    <div className="reason-meta">
                      <span>[{f.stage}]</span>
                      <span className="mono">{f.code}</span>
                    </div>
                    <div>{f.detail}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
