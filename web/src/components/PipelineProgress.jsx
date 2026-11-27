import { AlertTriangle, CheckCircle2, Circle, Loader2, XCircle } from 'lucide-react';

const STAGE_LABELS = [
  { key: 'extract', label: '1. Extraction (Agent 1)' },
  { key: 'registry', label: '2. Registry (Agent 2)' },
  { key: 'risk', label: '3. Risk Analysis (Agent 3)' },
  { key: 'recommend', label: '4. Recommend (Agent 4)' },
  { key: 'verify', label: '5. Verify (Agent 5)' },
  { key: 'report', label: '6. Final Report' },
];

function StageIcon({ state }) {
  if (state === 'done') return <CheckCircle2 size={15} color="#34d399" aria-hidden="true" />;
  if (state === 'running') return <Loader2 size={15} className="spin" color="#60a5fa" aria-hidden="true" />;
  if (state === 'failed') return <XCircle size={15} color="#f87171" aria-hidden="true" />;
  return <Circle size={15} color="#64748b" aria-hidden="true" />;
}

export default function PipelineProgress({ scan }) {
  if (!scan) return null;
  const stages = scan.stages || {};

  return (
    <section className="panel" aria-labelledby="progress-title">
      <div className="panel-header">
        <h2 id="progress-title" className="panel-title">
          Pipeline Execution Progress — <span className="mono">{scan.project_name}</span>
        </h2>
        <span
          className={`badge ${
            scan.status === 'done'
              ? 'badge-verified'
              : scan.status === 'failed'
              ? 'badge-rejected'
              : 'badge-review'
          }`}
        >
          {scan.status.toUpperCase()}
        </span>
      </div>

      <div className="stage-track" aria-live="polite">
        {STAGE_LABELS.map(({ key, label }) => {
          const state = stages[key] || 'pending';
          return (
            <div key={key} className={`stage-step ${state}`}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.4rem' }}>
                <span className="stage-step-name">{label}</span>
                <StageIcon state={state} />
              </div>
              <span className="stage-step-state">{state}</span>
            </div>
          );
        })}
      </div>

      {scan.status === 'failed' && (
        <div className="alert alert-error" role="alert">
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
          <div>
            <strong>Scan failed:</strong>{' '}
            {scan.error_message || 'Pipeline stopped with a stage failure. Inspect failures below.'}
          </div>
        </div>
      )}

      {Array.isArray(scan.failures) && scan.failures.length > 0 && (
        <div className="alert alert-warn" role="status">
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
          <div>
            <strong>Recorded Pipeline Notices ({scan.failures.length}):</strong>
            <ul style={{ margin: '0.35rem 0 0', paddingLeft: '1.1rem' }}>
              {scan.failures.slice(0, 6).map((f, idx) => (
                <li key={`${f.code}-${idx}`}>
                  <code className="mono">{f.code}</code>: {f.detail}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </section>
  );
}
