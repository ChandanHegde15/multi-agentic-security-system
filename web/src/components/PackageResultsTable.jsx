import { useMemo, useState } from 'react';
import { Info } from 'lucide-react';
import { findingTone } from '../reportUtils';

export default function PackageResultsTable({ rows, selectedId, onSelect }) {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((row) => {
      if (statusFilter !== 'all' && row.statusInfo.key !== statusFilter) return false;
      if (!q) return true;
      return (
        row.name.toLowerCase().includes(q) ||
        row.ecosystem.toLowerCase().includes(q) ||
        (row.reg?.status || '').toLowerCase().includes(q) ||
        (row.rec?.action || '').toLowerCase().includes(q)
      );
    });
  }, [rows, query, statusFilter]);

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        No dependencies were extracted from the submitted input.
      </div>
    );
  }

  return (
    <div>
      <div className="toolbar">
        <search>
          <input
            type="search"
            aria-label="Filter packages by name, ecosystem, or action"
            placeholder="Filter packages (name, ecosystem, action)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </search>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <label htmlFor="status-filter" style={{ margin: 0 }}>Status:</label>
          <select
            id="status-filter"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ width: 'auto' }}
          >
            <option value="all">All ({rows.length})</option>
            <option value="verified">Verified</option>
            <option value="suspicious">Suspicious</option>
            <option value="not_found">Not Found</option>
            <option value="needs_review">Needs Review</option>
            <option value="rejected">Rejected</option>
          </select>
        </div>
      </div>

      <div className="alert alert-info" style={{ marginBottom: '0.8rem' }}>
        <Info size={15} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
        <span>
          Click any package row to inspect full evidence, deterministic Agent 5 checks, and AI vs. rule reasoning.
          Packages marked <strong>Not Found</strong> are absent from the registry lookup and are not labeled confirmed malicious without malware evidence.
        </span>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Registry</th>
              <th>Risk Findings</th>
              <th>Evidence</th>
              <th>Recommendation</th>
              <th>Final Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => {
              const findings = row.risk?.findings || [];
              const targetLabel = row.rec?.target
                ? `${row.rec.target.package.name_normalized}${row.rec.target.version ? `@${row.rec.target.version}` : ''}`
                : null;
              const isSelected = row.dependency_id === selectedId;
              return (
                <tr
                  key={row.dependency_id}
                  className={isSelected ? 'selected' : ''}
                  onClick={() => onSelect(row.dependency_id)}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelect(row.dependency_id);
                    }
                  }}
                >
                  <td>
                    <div style={{ fontWeight: 600 }} className="mono">{row.name}</div>
                    <span className="badge badge-neutral" style={{ marginTop: 4 }}>{row.ecosystem}</span>
                  </td>
                  <td className="mono">{row.version}</td>
                  <td>
                    <span className="mono">{row.reg?.status || '—'}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                      {findings.map((f, idx) => (
                        <span key={`${f.finding}-${idx}`} className={`badge badge-${findingTone(f.finding)}`}>
                          {f.finding}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="mono">
                    {row.reg?.evidence_ids?.length || 0} record(s)
                  </td>
                  <td>
                    <span className="mono" style={{ fontWeight: 600 }}>{row.rec?.action || '—'}</span>
                    {targetLabel && (
                      <div className="hint mono">→ {targetLabel}</div>
                    )}
                  </td>
                  <td>
                    <span className={`badge badge-${row.statusInfo.tone}`}>
                      {row.statusInfo.label}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
