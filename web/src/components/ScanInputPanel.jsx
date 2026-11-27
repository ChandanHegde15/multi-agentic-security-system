import { useRef, useState } from 'react';
import { AlertCircle, FileCode2, FolderGit2, Play, Sparkles, Upload, X } from 'lucide-react';

const ALLOWED_EXTS = new Set([
  '.txt', '.in', '.json', '.py', '.pyw',
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts',
  '.sh', '.md', '.zip',
]);
const ALLOWED_NAMES = new Set([
  'dockerfile', 'requirements.txt', 'requirements.in',
  'package.json', 'package-lock.json', 'npm-shrinkwrap.json',
]);

function isSupportedFile(file) {
  const lower = file.name.toLowerCase();
  if (ALLOWED_NAMES.has(lower) || lower.startsWith('dockerfile')) return true;
  const dot = lower.lastIndexOf('.');
  if (dot === -1) return false;
  return ALLOWED_EXTS.has(lower.slice(dot));
}

export default function ScanInputPanel({ health, onSubmit, submitting }) {
  const [inputMode, setInputMode] = useState('files');
  const [projectName, setProjectName] = useState('');
  const [files, setFiles] = useState([]);
  const [text, setText] = useState('');
  const [gitUrl, setGitUrl] = useState('');
  const [variant, setVariant] = useState('R0');
  const [registryMode, setRegistryMode] = useState('snapshot');
  const [evidenceCutoff, setEvidenceCutoff] = useState('');
  const [verifierEnabled, setVerifierEnabled] = useState(true);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  const llmConfigured = Boolean(health?.llm?.local_model_ready);

  function addFiles(incoming) {
    setError('');
    const list = Array.from(incoming || []);
    if (list.length === 0) return;
    const unsupported = list.filter((f) => !isSupportedFile(f));
    if (unsupported.length > 0) {
      setError(
        `Unsupported file type: ${unsupported[0].name}. Supported: requirements.txt, package.json, package-lock.json, .py, .js/.ts, .sh, Dockerfile, .md, or .zip.`
      );
      return;
    }
    const hasZip = list.some((f) => f.name.toLowerCase().endsWith('.zip'));
    if (hasZip && (list.length > 1 || files.length > 0)) {
      setFiles([list.find((f) => f.name.toLowerCase().endsWith('.zip'))]);
      return;
    }
    setFiles((prev) => {
      const merged = [...prev.filter((p) => !p.name.toLowerCase().endsWith('.zip'))];
      for (const f of list) {
        if (!merged.some((m) => m.name === f.name)) merged.push(f);
      }
      return merged;
    });
  }

  function loadDemoSample() {
    setError('');
    setInputMode('files');
    setProjectName('Demo Mixed Project');
    setRegistryMode('snapshot');
    setVariant('R0');
    const reqs = new File(
      [
        'requests==2.32.3\n',
        'reqeusts-hallucinated==1.0.0\n',
        'timeoutpkg==1.0.0\n',
        'brokenpkg==1.0.0\n',
      ],
      'requirements.txt',
      { type: 'text/plain' }
    );
    const pkg = new File(
      [
        JSON.stringify(
          {
            name: 'demo-mixed-web',
            dependencies: {
              lodash: '^4.17.21',
              'strign-width': '1.0.0',
              'evil-pkg': '1.0.0',
            },
          },
          null,
          2
        ),
      ],
      'package.json',
      { type: 'application/json' }
    );
    setFiles([reqs, pkg]);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');

    if (inputMode === 'files' && files.length === 0) {
      setError('Select at least one manifest, code file, or .zip archive (or click "Load Demo Sample").');
      return;
    }
    if (inputMode === 'git' && !gitUrl.trim().startsWith('https://github.com/')) {
      setError('Enter a valid public GitHub repository URL starting with https://github.com/.');
      return;
    }
    if (inputMode === 'text' && !text.trim()) {
      setError('Paste code imports or prompted install commands (e.g. "$ pip install requests") before running.');
      return;
    }
    if (registryMode === 'live' && evidenceCutoff) {
      setError('Live registry mode cannot be used with an evidence cut-off date. Switch Registry Mode to "snapshot" or clear the cut-off date.');
      return;
    }
    if (variant !== 'R0' && !llmConfigured) {
      setError(`Variant ${variant} runs a local model on this computer. Start Ollama and run "ollama pull ${health?.llm?.local_model || 'qwen2.5:7b'}" once, or switch to R0 (Deterministic Rules).`);
      return;
    }

    try {
      await onSubmit({
        projectName: projectName.trim(),
        files: inputMode === 'files' ? files : [],
        text: inputMode === 'text' ? text : '',
        gitUrl: inputMode === 'git' ? gitUrl.trim() : '',
        variant,
        registryMode,
        evidenceCutoff: evidenceCutoff || null,
        verifierEnabled,
      });
    } catch (err) {
      setError(err.message || 'Could not start dependency scan.');
    }
  }

  return (
    <section className="panel" aria-labelledby="scan-form-title">
      <div className="panel-header">
        <h2 id="scan-form-title" className="panel-title">
          <Upload size={18} aria-hidden="true" />
          New Dependency Scan
        </h2>
        <button type="button" className="btn btn-secondary" onClick={loadDemoSample}>
          <Sparkles size={14} aria-hidden="true" />
          Load Demo Sample
        </button>
      </div>

      <div className="tablist" role="tablist" aria-label="Input source type">
        <button
          type="button"
          role="tab"
          className="tab-btn"
          aria-selected={inputMode === 'files'}
          onClick={() => { setInputMode('files'); setError(''); }}
        >
          <Upload size={14} aria-hidden="true" />
          Files / ZIP
        </button>
        <button
          type="button"
          role="tab"
          className="tab-btn"
          aria-selected={inputMode === 'git'}
          onClick={() => { setInputMode('git'); setError(''); }}
        >
          <FolderGit2 size={14} aria-hidden="true" />
          GitHub URL
        </button>
        <button
          type="button"
          role="tab"
          className="tab-btn"
          aria-selected={inputMode === 'text'}
          onClick={() => { setInputMode('text'); setError(''); }}
        >
          <FileCode2 size={14} aria-hidden="true" />
          Paste Snippet
        </button>
      </div>

      {error && (
        <div className="alert alert-error" role="alert">
          <AlertCircle size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate>
        <div className="form-group">
          <label htmlFor="project-name">Project Name (optional)</label>
          <input
            id="project-name"
            name="project_name"
            type="text"
            placeholder="e.g. final-year-demo"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            maxLength={64}
          />
        </div>

        {inputMode === 'files' && (
          <div className="form-group">
            <label htmlFor="manifest-upload">Manifests, Code Files, or ZIP Archive</label>
            <div
              className={`dropzone ${dragging ? 'active' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                addFiles(e.dataTransfer.files);
              }}
              onClick={() => fileInputRef.current?.click()}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  fileInputRef.current?.click();
                }
              }}
              role="button"
              tabIndex={0}
              aria-label="Drop dependency files or click to browse"
            >
              <p style={{ margin: 0, fontWeight: 500 }}>
                Drop files here or click to browse
              </p>
              <p className="hint" style={{ margin: '0.35rem 0 0' }}>
                requirements.txt, package.json, package-lock.json, .py, .js/.ts, Dockerfile, .sh, .md, or .zip
              </p>
              <input
                ref={fileInputRef}
                id="manifest-upload"
                type="file"
                multiple
                style={{ display: 'none' }}
                onChange={(e) => {
                  addFiles(e.target.files);
                  e.target.value = '';
                }}
              />
            </div>
            {files.length > 0 && (
              <ul className="file-list">
                {files.map((f) => (
                  <li key={f.name} className="file-chip">
                    <span className="mono">{f.name}</span>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      aria-label={`Remove ${f.name}`}
                      onClick={() => setFiles((prev) => prev.filter((item) => item.name !== f.name))}
                    >
                      <X size={14} aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {inputMode === 'git' && (
          <div className="form-group">
            <label htmlFor="git-url">Public GitHub Repository URL</label>
            <input
              id="git-url"
              name="git_url"
              type="url"
              placeholder="https://github.com/owner/repository"
              value={gitUrl}
              onChange={(e) => setGitUrl(e.target.value)}
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
            />
            <span className="hint">
              Downloaded in memory as a ZIP archive; never cloned or executed.
            </span>
          </div>
        )}

        {inputMode === 'text' && (
          <div className="form-group">
            <label htmlFor="pasted-text">Code Imports or Install Commands</label>
            <textarea
              id="pasted-text"
              name="text"
              placeholder={'$ pip install reqeusts-hallucinated\n$ npm install strign-width'}
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
            />
            <span className="hint">
              Prefix shell commands with <code>$ </code> or wrap them in fenced Markdown code blocks.
            </span>
          </div>
        )}

        <div className="form-row">
          <div className="form-group">
            <label htmlFor="variant-select">Agent 4 Recommender</label>
            <select
              id="variant-select"
              name="variant"
              value={variant}
              onChange={(e) => setVariant(e.target.value)}
            >
              <option value="R0">R0 — Deterministic Rules (Offline)</option>
              <option value="LLM-G">
                LLM-G — Grounded LLM {llmConfigured ? '(Local, Ready)' : '(Start Ollama)'}
              </option>
              <option value="LLM-U">
                LLM-U — Ungrounded LLM {llmConfigured ? '(Local, Ready)' : '(Start Ollama)'}
              </option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="registry-select">Agent 2 Registry Mode</label>
            <select
              id="registry-select"
              name="registry_mode"
              value={registryMode}
              onChange={(e) => setRegistryMode(e.target.value)}
            >
              <option value="snapshot">Snapshot (Recorded Fixtures)</option>
              <option value="live">Live (PyPI / npm Metadata)</option>
              <option value="off">Off (Evidence Store Only)</option>
            </select>
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="cutoff-date">Evidence Cut-off Date (optional)</label>
          <input
            id="cutoff-date"
            name="evidence_cutoff"
            type="date"
            value={evidenceCutoff}
            onChange={(e) => setEvidenceCutoff(e.target.value)}
          />
          <span className="hint">Hides evidence published on/after this date (for temporal hold-out demos).</span>
        </div>

        <div className="checkbox-row">
          <input
            id="verifier-toggle"
            type="checkbox"
            checked={verifierEnabled}
            onChange={(e) => setVerifierEnabled(e.target.checked)}
          />
          <label htmlFor="verifier-toggle" style={{ margin: 0, color: 'var(--text-primary)' }}>
            Enforce Agent 5 Deterministic Verifier Gate
          </label>
        </div>

        <button type="submit" className="btn btn-primary" disabled={submitting}>
          <Play size={16} aria-hidden="true" />
          {submitting ? 'Starting Multi-Agent Scan...' : 'Start Dependency Analysis'}
        </button>
      </form>
    </section>
  );
}
