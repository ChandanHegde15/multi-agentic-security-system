# Paper comparison matrix

Status 2026-11-13. Built from `PAPER_INVENTORY.md`; page references are there. A cell reflects only the parts of a paper that were read (see "Read depth" in the inventory). "No" means "not found in the parts read", which is weaker than "the paper does not do it" for papers read partially.

## Terminology used in every table

These terms are kept apart throughout:

| Term | Meaning here |
|---|---|
| Nonexistent | A name with no package in the registry at a stated time |
| Hallucinated | A name or API produced by an LLM that does not exist; says nothing about malice |
| Typosquat | A registered name chosen to be confused with another; not necessarily malware |
| Malicious | A package reported or confirmed to contain harmful code |
| Vulnerable | A legitimate package with a known flaw in some versions |
| Registry existence | The package can be found in the registry; not evidence of safety |
| Verified detection | A detector's verdict that a second mechanism has confirmed |
| Verified remediation | A recommended fix that a second mechanism has checked |
| Recommendation | A stated fix for a specific flagged dependency (remove, replace, upgrade) |

## 1. Problem, data and ground truth

| ID | Research problem | Risk category studied | Dataset | How ground truth is established |
|---|---|---|---|---|
| P002 | Workflow cost of code hallucinations | Hallucinated APIs, parameters, nonexistent libraries | Synthetic sessions | **Author-assigned rates; no ground truth** |
| P003 | Types, causes, impacts of code hallucinations | Hallucinated code (requirement, consistency, knowledge) | 3,120 generated samples (HumanEval, CoderEval) | Manual open coding by ten annotators with a codebook |
| P004 | Reliable LLM analysis of malicious PyPI packages | Malicious | 500 malicious (MalRegistry), 2,500 benign (new PyPI uploads) | Malicious: membership in a public malware collection. Benign: recency, **assumed** |
| P005 | LLM detection of malicious npm code | Malicious | 5,115 npm packages (MalwareBench subset) | Package labels from the benchmark; file labels by two researchers reviewing model reports |
| P007 | Security-related hallucinations (review) | Hallucinated packages, APIs, security logic | 16 studies, 2024–2025 | Not applicable |
| P010 | Imprecise supply-chain terminology | All (conceptual) | None | Not applicable |
| P017 | Risk signals for dependency selection | Malicious (weak links), vulnerable | Scorecard data, npm metadata, survey of 470 developers | Advisory databases; registry metadata |
| P018 | Semver use and update flow in npm | Vulnerable (update propagation) | Entire npm registry history | GitHub Security Advisory database |
| P020 | Prevalence of malicious packages in npm and PyPI | Malicious; vulnerable (descriptive) | DataDog, OpenSSF, MalRegistry lists; HackerOne reports | Membership in public lists; authors note possible false positives |
| P022 | Detecting malicious npm packages | Malicious; uses typosquat-style name signals | 6,126 malicious (vendors, Backstabber's, MalOSS); popular packages as benign | Vendor and collection labels; popularity as benign, **assumed** |
| P023 | Detecting malicious npm packages with LLM-made features | Malicious | 3,258 malicious, 4,051 benign (MalnpmDB) | Two-researcher manual confirmation; popularity as benign, **assumed** |
| P024 | Vulnerability lifecycle and propagation in npm | Vulnerable | 399 Snyk reports, libraries.io history | Advisory version constraints (lower bounds often missing) |
| P025 | Practical detection of malicious npm packages | Malicious | 643 malicious versions from npm, 1,147 benign; 96,287 live versions | npm's own archive; manual triage; takedown by npm as confirmation |
| P026 | Security of JavaScript GitHub Actions | Vulnerable; code weaknesses | 8,107 Actions | Advisory data; CodeQL findings |
| P027 | Practical detection of malicious npm packages | Malicious | Public malicious npm sets; three months of new packages | Public disclosure; manual confirmation; takedown by npm |
| P001, P006, P008, P009, P011–P016, P019 | Other domains, frameworks, blockchain registries, one incident study | Not package-level, or none | None, simulation, single case or single project | None, or not applicable |

Observations:

- **No paper in the archives has ground truth for a nonexistent or hallucinated package name, for a typosquat pair, or for a correct remediation.**
- Malicious labels come from public collections, vendors or registry takedowns. Only P023 and P005 add independent manual confirmation.
- Benign labels are assumed from popularity or recency in P004, P022 and P023. None verifies them.

## 2. Method, LLM use, retrieval, verification, recommendation

| ID | Method | LLM involvement | Retrieval / external evidence | Independent verification of output | Remediation recommendation |
|---|---|---|---|---|---|
| P002 | Conceptual impact model | Subject of study only | Mentions registry grounding as advice | No | No (general advice) |
| P003 | Taxonomy; prompt-level mitigation | Generates code; mitigated with Self-Refine, CoT, RAG | **Yes**: repository code retrieved into the prompt | No. Evaluation by tests and manual labels | No |
| P004 | Supervisor–worker agents, Plan-and-Execute | **Yes**: three local models in separate roles | **Yes**: web search, URL fetch, VirusTotal through tools | **Partly**: deterministic tools produce intermediate facts; the final verdict and report are LLM output, unverified. Supervisor reviews workers (same model family) | Report contains recommendations; a reviewer found them "unclear who these are for"; not evaluated |
| P005 | Prompted code-review workflow | **Yes**: GPT-3, GPT-4 | No | **No independent check**: self-refinement and LLM-as-a-Judge by the same model. CodeQL is a pre-screener, not a verifier | No |
| P007 | Systematic review | Subject of study | Reports retrieval as a mitigation class | Reports "validation and tooling" (package-existence checks, static analysis) as a mitigation class | Reports static-analysis-driven patching of code flaws; nothing for dependencies |
| P017 | Metric evaluation, regression | No | Scorecard and registry data | No | No (risk assessment of candidates) |
| P018 | Time-travelling dependency resolver | No | Registry history | Not applicable | No |
| P020 | Descriptive counting | No | Public lists | No | General mitigations, unevaluated |
| P022 | Feature-based ML plus second-pass detector | No | No | Second detector re-checks packages judged benign | No |
| P023 | LLM-generated features, ML classifier | **Yes**: feature generation only | No | Frequency threshold filters LLM answers | No |
| P024 | Survival analysis over versions | No | Advisory and release history | Not applicable | No. Measures whether an upgrade is possible |
| P025 | ML classifier, then reproducer and clone detector | No | Source repository for reproduction | **Yes, deterministic, of a detection**: reproducible-from-source filter removes false positives | No |
| P026 | Dependency-network and static analysis | No | Advisory data | Not applicable | No |
| P027 | Behaviour-graph matching, then verifier | **Yes**: API recognition, command judgement, argument judgement | No | **Yes, of a detection, LLM-judged**: sandbox execution collects arguments, an LLM decides | No |
| P001 | KG retrieval plus LLM (robotics) | Yes | Yes (knowledge graph) | Human review only | Recommended next actions for a robot fault; unevaluated |
| P006 | Multi-LLM generation and judging | Yes | No | LLM judges only | No |

Observations:

- **Verification of a detection exists** (P025 deterministic, P027 LLM-based, P022 second pass). **Verification of a recommendation does not appear in any archive paper.**
- **A deterministic tool inside an LLM pipeline exists** (P004, P005). In both it supplies or filters inputs; in neither does it check the final LLM output.
- **Retrieval or grounding exists** (P003, P004, P001; P007 as a reviewed class).
- **Multi-agent LLM design exists** (P004).
- Every malicious-package paper stops at a verdict or a report. None says what the consuming project should use instead.

## 3. Evaluation, baselines, limitations

| ID | Metrics | Baselines | Unresolved, by the authors' own statement |
|---|---|---|---|
| P002 | Task time, pass rate, rework (illustrative) | Own low-hallucination condition | Needs "large-scale, real-world experiments" |
| P003 | Type shares, pass@1, hallucinatory samples | Original prompt versus three strategies | Automated detection; fact-checking tools; other tasks |
| P004 | Precision, recall, F1, FPR, time; Likert survey | MalGuard, GuardDog; single-agent variant | Over-assesses risk in benign code; conflates insecure and malicious; only entry-point files; 820 first-trial timeouts |
| P005 | Precision, recall, F1, cost | CodeQL | Hallucination and mode collapse; no file-level ground truth; registry does not confirm reports |
| P007 | — | — | No framework measures "the full lifecycle impact"; benchmarks fragmented; grounding "insufficient under ambiguous conditions" |
| P017 | Vulnerability count, MTTR, MTTU | — | Removed npm packages lose metadata; practices correlate with more reported vulnerabilities (confounding) |
| P018 | Update and constraint shares, flow delay | — | Deleted and unpublished packages cannot be studied |
| P020 | Counts | — | Lists may contain false positives and miss malware; calls for comparing detection tools and studying developer install decisions |
| P022 | Accuracy, precision, recall, F1 | GuardDog, SAP | None stated |
| P023 | FPR, FNR | Existing detectors | Train/test not independent; weak on Python; obfuscation |
| P024 | Time to discovery and fix; affected share | — | Advisory ranges lack lower bounds; >40% of dependents cannot be fixed by upgrade |
| P025 | TP and FP after triage; precision, recall; time | Three classifiers | Copy-cat clusters bias the corpus; reproducer rarely succeeds |
| P026 | Affected shares | — | Declared dependencies may be unused; SCA tools do not confirm exploitability |
| P027 | Precision, recall, F1, FPR | GuardDog, SAP, Amalfi, Cerebro | 38.2% false positives in live use |

## 4. What the matrix shows across papers

1. **Family coverage is lopsided.** Malicious: 7 papers (P004, P005, P020, P022, P023, P025, P027). Vulnerable: 4 (P018, P024, P026, P017 in part). Hallucinated code: 3 (P002, P003, P007), none with package-name ground truth. Typosquat: none as a primary topic. Nonexistent: none.
2. **No paper evaluates more than one of the four families with separate labels.** P020 describes malicious packages and vulnerabilities side by side but only counts them.
3. **The end point of every pipeline is a verdict.** Remediation appears as general advice (P020, P011), as a property of the ecosystem (P024, P018) or as an unevaluated report section (P004).
4. **Independent checks target false positives of detectors**, never the safety of a suggested fix.
5. **Benign ground truth is assumed, not verified**, in every detector paper that needs it.

These are statements about 26 papers selected into three archives. They do not describe the whole literature; see `NOVELTY_ASSESSMENT.md` §4 for the external check.
