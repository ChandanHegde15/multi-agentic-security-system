// Utility helpers mapping raw pipeline/0.2 contract records into UI rows.

const SUSPICIOUS_FINDINGS = new Set([
  'malicious_reported',
  'compromised_version',
  'typosquat_listed',
  'vulnerable',
  'registry_security_hold',
  'name_similar_to_popular',
]);

export function classifyDependencyStatus(dep, reg, risk, rec, ver, verifierEnabled = true) {
  const findings = (risk?.findings || []).map((f) => f.finding);
  const hasSuspicious = findings.some((f) => SUSPICIOUS_FINDINGS.has(f));
  const isNotFound = reg?.status === 'not_found' || findings.includes('nonexistent');

  if (verifierEnabled && ver?.verdict === 'reject') {
    return { label: 'Rejected', tone: 'rejected', key: 'rejected' };
  }
  if (hasSuspicious) {
    return { label: 'Suspicious', tone: 'suspicious', key: 'suspicious' };
  }
  if (isNotFound) {
    return { label: 'Not Found', tone: 'neutral', key: 'not_found' };
  }
  if (verifierEnabled && ver?.verdict === 'abstain') {
    return { label: 'Needs Review', tone: 'review', key: 'needs_review' };
  }
  if (findings.includes('unknown') || reg?.status === 'lookup_error' || reg?.status === 'invalid_response') {
    return { label: 'Needs Review', tone: 'review', key: 'needs_review' };
  }
  if (!verifierEnabled || ver?.verdict === 'accept') {
    return { label: 'Verified', tone: 'verified', key: 'verified' };
  }
  return { label: 'Needs Review', tone: 'review', key: 'needs_review' };
}

export function indexReportRows(report, verifierEnabled = true) {
  if (!report) return [];
  const deps = report.extraction?.dependencies || [];
  const regMap = new Map((report.registry?.results || []).map((r) => [r.dependency_id, r]));
  const riskMap = new Map((report.risk?.assessments || []).map((a) => [a.dependency_id, a]));
  const recMap = new Map((report.recommendations?.recommendations || []).map((r) => [r.dependency_id, r]));
  const verMap = new Map((report.verification?.verifications || []).map((v) => [v.dependency_id, v]));

  return deps.map((dep) => {
    const reg = regMap.get(dep.dependency_id) || null;
    const risk = riskMap.get(dep.dependency_id) || null;
    const rec = recMap.get(dep.dependency_id) || null;
    const ver = verMap.get(dep.dependency_id) || null;
    const statusInfo = classifyDependencyStatus(dep, reg, risk, rec, ver, verifierEnabled);
    return {
      dependency_id: dep.dependency_id,
      name: dep.package?.name_normalized || dep.original_declaration,
      ecosystem: dep.ecosystem || 'unresolved',
      version: dep.version_constraint_raw || 'unpinned',
      dep,
      reg,
      risk,
      rec,
      ver,
      statusInfo,
    };
  });
}

export function verdictBadge(verdict) {
  if (verdict === 'accept') return { label: 'Verified (accept)', tone: 'verified' };
  if (verdict === 'reject') return { label: 'Rejected (reject)', tone: 'rejected' };
  return { label: 'Needs Review (abstain)', tone: 'review' };
}

export function findingTone(finding) {
  if (finding === 'malicious_reported' || finding === 'compromised_version' || finding === 'registry_security_hold') {
    return 'rejected';
  }
  if (finding === 'typosquat_listed' || finding === 'vulnerable' || finding === 'name_similar_to_popular') {
    return 'suspicious';
  }
  if (finding === 'unknown') return 'review';
  if (finding === 'no_evidence' || finding === 'withdrawn_only') return 'verified';
  return 'neutral';
}
