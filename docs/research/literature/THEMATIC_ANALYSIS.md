# Thematic analysis

Status 2026-11-13. Groups the 26 distinct archive papers by what they actually contain. Paper IDs and page references are in `PAPER_INVENTORY.md`. A paper can appear under several themes.

## 1. Themes found

The candidate category list was adjusted to the contents:

- **Kept:** hallucination in LLM-generated code; malicious package detection; LLM-based security analysis; agentic security systems; evidence-grounded generation; vulnerability propagation and updating; software supply-chain security in general.
- **Added:** verification of a detector's output; supply-chain risk frameworks and scoring; blockchain-based registries and provenance; ground-truth and dataset practice.
- **Empty in these archives:** slopsquatting as a primary topic; typosquatting and combosquatting detection; package registry verification; dependency confusion; automated dependency remediation; recommendation verification. These are covered only by externally verified sources.

| Theme | Papers | Evidence strength in the archives |
|---|---|---|
| T1. Hallucination in LLM-generated code | P003, P007, P002 | One journal study with manual labels (P003), one review (P007), one synthetic paper (P002) |
| T2. Malicious package detection (non-LLM) | P022, P025, P020 (descriptive) | Two detector papers, one at ICSE |
| T3. LLM-based malicious package analysis | P004, P005, P023, P027 | Four papers, three at ICSE, ASE or in IEEE TIFS |
| T4. Agentic and multi-stage LLM security systems | P004, P027, P005 | One multi-agent system; two staged pipelines |
| T5. Evidence grounding and retrieval | P003, P004, P007, P001 | Measured in P003; reviewed in P007; designed but unmeasured in P001 |
| T6. Verification of a detector's output | P025, P027, P022, P004 | Measured by ablation in P027; described in P025 |
| T7. Vulnerability propagation, versions and updating | P024, P018, P026, P012, P017 | Three MSR measurement studies |
| T8. Dependency-selection risk signals and frameworks | P017, P008, P009, P014 | One doctoral proposal with prior results; three descriptive papers |
| T9. Supply-chain attack overviews and terminology | P020, P010, P011, P014 | Descriptive |
| T10. Blockchain registries and provenance | P013, P015, P016 | Proofs of concept and simulation |
| T11. Ground truth and dataset practice | P023, P005, P025, P020, P004 | Statements inside detector papers |
| T12. Outside the field | P001 (robotics), P006 (documentation), P019 (runtime protection) | — |

## 2. What each theme establishes

### T1. Hallucination in LLM-generated code

- Hallucination in code is categorised and measured. P003 finds knowledge conflicts are about a third of hallucinations, most of them about libraries and project context.
- P007 lists nonexistent packages as one of five security-relevant hallucination types and reports rates from about 5% to over 20% (second-hand, from the studies it reviews).
- Mitigation classes are known: grounding and retrieval, feedback-driven refinement, validation and tooling, prompt controls (P007). Retrieval halved hallucinatory samples in one small experiment (P003).
- **Limits stated by the papers:** grounding is "insufficient under ambiguous conditions" (P007); mitigation can break outputs that were correct (P003); nothing measures the lifecycle from generation to exploitation (P007).
- **Not in this theme:** what happens after a hallucinated dependency is detected. P007's mitigation for package hallucination is an existence check, allowlists and CI checks. None of the three papers considers a wrong name that resolves to an existing package, or what should replace a rejected one.

### T2 and T3. Malicious package detection, without and with LLMs

- This is the most developed theme: seven papers, with strong reported accuracy (P004 recall 0.984 at 0.08% false positives; P005 GPT-4 precision 0.99; P023 false-positive rate 1.3%).
- All work on package **code** (and sometimes metadata), and all need package samples.
- Live deployment is much harder than benchmark results suggest: P027 reports 38.2% false positives over three months as the best of five tools; P025 relies on retraining to bring false positives down.
- LLM roles vary: full analyst (P004, P005), feature generator (P023), component judge (P027).
- **Limits stated by the papers:** LLM hallucination and mode collapse (P005), conflating insecure with malicious (P004), train/test dependence (P023), copy-cat clusters (P025), weak transfer from npm to Python (P023).
- **Not in this theme:** any statement of what a project that depends on a flagged package should do.

### T4. Agentic and multi-stage LLM systems

- P004 is a complete multi-agent design with role separation, state-based communication, small toolsets and deterministic tools, with a single-agent comparison.
- Its central claim is that reliability comes "from architecting systems that compensate for LLM weaknesses".
- Consequence: a multi-agent pipeline, role separation and tool use are established designs. They cannot be offered as contributions.

### T5. Evidence grounding

- Present as repository retrieval (P003), threat-intelligence lookup through tools (P004) and knowledge-graph retrieval with a rule that each hypothesis cite evidence (P001, unevaluated).
- No archive paper **measures** whether the claims in an LLM's security output are supported by the evidence it was given. P004's report quality is judged by three people on a Likert scale.

### T6. Verification of a detector's output

- P025: a classifier's positive is discarded if the package can be rebuilt from its public source. Deterministic, cheap, low coverage.
- P027: a matched behaviour is confirmed by running the package in a sandbox and asking an LLM about the observed arguments. Ablated.
- P022: packages judged benign get a second detector pass.
- In every case the verified object is a **detection**, the purpose is to cut false positives or false negatives, and code is analysed or executed.
- The "generate, then verify" pattern is therefore established for detection. Its application to recommendations is not present in the archives.

### T7. Vulnerability propagation, versions and updating

- Fixes do not reach dependents automatically: more than 40% of dependent releases could not adopt a fix because of their own constraints (P024, 2018 data).
- Most security patches are patch-level releases, with outliers released as minor or major versions (P018).
- Advisory ranges are imprecise: most give only an upper bound (P024).
- A declared vulnerable dependency is not proof of exposure (P026).
- An incident response can be a **downgrade** (P011, XZ Utils).
- Together these show that "upgrade to the fixed version" is a simplification. A remediation can satisfy an advisory range and still be inapplicable, costly or, for compromised versions, pointed in the wrong direction.

### T8 and T9. Risk frameworks, overviews, terminology

- P017 proposes metadata signals for choosing dependencies and reports that a higher practice score coincided with more reported vulnerabilities, a warning against single scores.
- P010 argues that vulnerable dependencies, typosquatting and build compromise are "very different in nature" and that lumping them hinders defence.
- P020 keeps vulnerabilities and malicious code apart in its definitions (while swapping the typosquatting and combosquatting definitions).

### T10. Blockchain registries

- Three papers address registry integrity and traceability. None addresses name confusion, hallucination or remediation, and none has an empirical evaluation. Not relevant to this project.

### T11. Ground truth and dataset practice

- Malicious samples disappear: npm removes them and replaces the metadata (P017), takes them down immediately (P025), and deleted packages cannot be scraped (P018).
- Public malicious lists overlap and contain errors: 812 packages shared by three sources; possible false positives acknowledged (P020).
- "Benign" is assumed from popularity or recency (P004, P022, P023).
- File-level or behaviour-level truth usually does not exist and is created by the researchers (P005, P023).
- Registries rarely confirm reports (P005); takedown is used as confirmation where available (P025, P027).

## 3. Cross-theme observations

1. **The archives describe a pipeline that ends one step early.** Hallucination work ends at "validate the dependency"; detection work ends at "this package is malicious"; vulnerability work ends at "a fix exists and often does not propagate". The step where a developer or an assistant chooses the replacement, removal or version is not studied.
2. **Reliability of LLM security output is a recognised problem with an established response**: surround the LLM with deterministic components (P004, P005, P025's pattern). The response has been applied to detection.
3. **The risk families are studied by separate communities with separate data.** Hallucination papers do not use malicious-package lists; malicious-package papers do not consider nonexistent names; vulnerability papers do not consider malice. The only cross-family statements are conceptual (P010) or descriptive (P020).
4. **Data problems recur and match this project's own findings**: vanishing samples, overlapping lists, assumed benign labels, imprecise advisory ranges.
5. **The archives are npm-heavy for malware and vulnerabilities** (P005, P018, P022–P027) and PyPI-specific only in P004 and P020. This project is PyPI-first.

## 4. Composition and selection bias of the archives

- Archive A2 consists mostly of short conference papers on frameworks and blockchain designs with little or no evaluation (P008, P009, P013–P016). They add breadth, not evidence.
- The strongest venues are in A3 and A1: ICSE (P005, P025), ASE (P027), MSR (P018, P024, P026), IEEE TSE (P003), IEEE TIFS (P023), AIware (P004).
- The key papers for this project's topic are **not in the archives**: the package-hallucination measurement studies, typosquatting and package-confusion detection, dependency-decision benchmarks and automated update studies. A gap analysis from the archives alone would overstate how unexplored the topic is. `NOVELTY_ASSESSMENT.md` therefore combines the archives with the externally verified sources.
