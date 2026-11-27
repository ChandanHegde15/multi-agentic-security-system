import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  HelpCircle,
  Shield,
  ShieldAlert,
  XCircle,
} from 'lucide-react';
import { fetchHealth, fetchScanDetail, fetchScans, submitScan } from './api';
import AgentTabsView from './components/AgentTabsView';
import PackageDetailView from './components/PackageDetailView';
import PipelineProgress from './components/PipelineProgress';
import ScanInputPanel from './components/ScanInputPanel';
import { indexReportRows } from './reportUtils';

export default function App() {
  const [health, setHealth] = useState(null);
  const [healthErr, setHealthErr] = useState('');
  const [stats, setStats] = useState({
    total_scans: 0,
    completed_scans: 0,
    failed_scans: 0,
    packages_analyzed: 0,
    verified: 0,
    suspicious: 0,
    not_found: 0,
    needs_review: 0,
    rejected: 0,
  });
  const [recentScans, setRecentScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [selectedDepId, setSelectedDepId] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const refreshHistory = useCallback(async () => {
    try {
      const data = await fetchScans(20);
      setStats(data.stats);
      setRecentScans(data.scans || []);
    } catch {
      // handled via health banner
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then((data) => {
        if (!cancelled) {
          setHealth(data);
          setHealthErr('');
        }
      })
      .catch((err) => {
        if (!cancelled) setHealthErr(err.message || 'Backend API unavailable.');
      });
    fetchScans(20)
      .then((data) => {
        if (!cancelled) {
          setStats(data.stats);
          setRecentScans(data.scans || []);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  // Poll active scan while queued/running
  useEffect(() => {
    if (!activeScan || (activeScan.status !== 'running' && activeScan.status !== 'queued')) {
      return undefined;
    }
    const timer = setInterval(async () => {
      try {
        const updated = await fetchScanDetail(activeScan.scan_id);
        setActiveScan(updated);
        if (updated.status === 'done' || updated.status === 'failed') {
          refreshHistory();
        }
      } catch {
        // transient poll error ignored until next tick
      }
    }, 450);
    return () => clearInterval(timer);
  }, [activeScan, refreshHistory]);

  async function handleStartScan(payload) {
    setSubmitting(true);
    setSelectedDepId(null);
    try {
      const created = await submitScan(payload);
      setActiveScan(created);
      refreshHistory();
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSelectHistory(scanId) {
    setSelectedDepId(null);
    try {
      const detail = await fetchScanDetail(scanId);
      setActiveScan(detail);
    } catch (err) {
      setHealthErr(err.message || 'Could not load scan.');
    }
  }

  const rows = useMemo(() => {
    if (!activeScan?.report) return [];
    return indexReportRows(activeScan.report, activeScan.verifier_enabled !== false);
  }, [activeScan]);

  const selectedRow = useMemo(
    () => rows.find((r) => r.dependency_id === selectedDepId) || null,
    [rows, selectedDepId]
  );

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={24} aria-hidden="true" />
          </div>
          <div>
            <h1>Multi-Agentic Dependency Security System</h1>
            <p>
              Five-agent defense against AI-hallucinated package poisoning, typosquatting, and unsafe remediation.
            </p>
          </div>
        </div>

        <div className="health-pills">
          {health ? (
            <>
              <span className="pill ok">
                <Activity size={13} aria-hidden="true" />
                API Online
              </span>
              <span className="pill">
                <Database size={13} aria-hidden="true" />
                Evidence Store ({health.evidence_store?.source}): {health.evidence_store?.records_indexed ?? 0} records
              </span>
              <span className={`pill ${health.llm?.local_model_ready ? 'ok' : ''}`}>
                LLM: {health.llm?.local_model_ready ? `Local model (${health.llm.local_model})` : 'Rules R0 Ready'}
              </span>
            </>
          ) : (
            <span className="pill err">
              <AlertTriangle size={13} aria-hidden="true" />
              {healthErr || 'Connecting to backend...'}
            </span>
          )}
        </div>
      </header>

      <main>
        {/* Real Aggregate KPI Cards */}
        <section className="stats-grid" aria-label="Aggregate security metrics">
          <div className="stat-card">
            <div className="stat-label">
              <span>Packages Analyzed</span>
              <Activity size={15} aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.packages_analyzed}</div>
          </div>
          <div className="stat-card verified">
            <div className="stat-label">
              <span>Verified (Accept)</span>
              <CheckCircle2 size={15} color="#34d399" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.verified}</div>
          </div>
          <div className="stat-card suspicious">
            <div className="stat-label">
              <span>Suspicious</span>
              <ShieldAlert size={15} color="#fbbf24" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.suspicious}</div>
          </div>
          <div className="stat-card rejected">
            <div className="stat-label">
              <span>Rejected Recs</span>
              <XCircle size={15} color="#f87171" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.rejected}</div>
          </div>
          <div className="stat-card review">
            <div className="stat-label">
              <span>Needs Review</span>
              <HelpCircle size={15} color="#38bdf8" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.needs_review}</div>
          </div>
        </section>

        <div className="workspace-grid">
          {/* Left Column: Input + Recent Activity */}
          <div>
            <ScanInputPanel health={health} onSubmit={handleStartScan} submitting={submitting} />

            <section className="panel" aria-labelledby="history-title">
              <div className="panel-header">
                <h2 id="history-title" className="panel-title">
                  <Clock size={17} aria-hidden="true" />
                  Recent Scans ({stats.total_scans})
                </h2>
              </div>
              {recentScans.length === 0 ? (
                <p className="hint" style={{ margin: 0 }}>
                  No scans recorded yet. Submit a project or click &ldquo;Load Demo Sample&rdquo; above.
                </p>
              ) : (
                <ul className="history-list">
                  {recentScans.map((item) => (
                    <li key={item.scan_id}>
                      <button
                        type="button"
                        className={`history-btn ${activeScan?.scan_id === item.scan_id ? 'active' : ''}`}
                        onClick={() => handleSelectHistory(item.scan_id)}
                      >
                        <div>
                          <div style={{ fontWeight: 600 }}>{item.project_name}</div>
                          <div className="hint mono">
                            {item.variant} · {item.registry_mode} · {item.metrics?.packages_analyzed ?? '…'} pkg(s)
                          </div>
                        </div>
                        <span
                          className={`badge ${
                            item.status === 'done'
                              ? 'badge-verified'
                              : item.status === 'failed'
                              ? 'badge-rejected'
                              : 'badge-review'
                          }`}
                        >
                          {item.status}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>

          {/* Right Column: Live Progress + Results + Package Inspector */}
          <div>
            {!activeScan ? (
              <section className="panel empty-state">
                <Shield size={36} color="#3b82f6" style={{ marginBottom: '0.6rem' }} aria-hidden="true" />
                <h2 style={{ margin: '0 0 0.4rem', fontSize: '1.1rem' }}>Ready for Dependency Verification</h2>
                <p style={{ margin: '0 auto', maxWidth: 520, color: 'var(--text-secondary)' }}>
                  Upload a project manifest, paste install commands, or enter a public GitHub URL on the left.
                  Agents 1–5 will extract dependencies, collect evidence, analyze risks, propose remediations,
                  and independently verify every recommendation before displaying it.
                </p>
              </section>
            ) : (
              <>
                <PipelineProgress scan={activeScan} />
                {selectedRow && (
                  <PackageDetailView
                    row={selectedRow}
                    verifierEnabled={activeScan.verifier_enabled !== false}
                    onClose={() => setSelectedDepId(null)}
                  />
                )}
                {activeScan.report && (
                  <AgentTabsView
                    scan={activeScan}
                    rows={rows}
                    selectedId={selectedDepId}
                    onSelect={setSelectedDepId}
                  />
                )}
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
