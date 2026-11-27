const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

async function parseError(res) {
  try {
    const data = await res.json();
    if (data && typeof data.detail === 'string') return data.detail;
  } catch {
    // ignore json parse failure
  }
  return `Request failed with HTTP ${res.status}`;
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/api/health`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function fetchScans(limit = 25) {
  const res = await fetch(`${API_BASE}/api/scans?limit=${limit}`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function submitScan({
  projectName,
  files,
  text,
  gitUrl,
  variant,
  registryMode,
  evidenceCutoff,
  verifierEnabled,
}) {
  const form = new FormData();
  if (projectName) form.append('project_name', projectName);
  if (files && files.length > 0) {
    for (const file of files) {
      form.append('files', file, file.name);
    }
  }
  if (text && text.trim()) form.append('text', text);
  if (gitUrl && gitUrl.trim()) form.append('git_url', gitUrl.trim());
  form.append('variant', variant || 'R0');
  form.append('registry_mode', registryMode || 'snapshot');
  if (evidenceCutoff) form.append('evidence_cutoff', evidenceCutoff);
  form.append('verifier_enabled', verifierEnabled ? 'true' : 'false');

  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'POST',
    body: form,
  });
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function fetchScanDetail(scanId) {
  const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export function getExportUrl(scanId) {
  return `${API_BASE}/api/scans/${encodeURIComponent(scanId)}/export`;
}
