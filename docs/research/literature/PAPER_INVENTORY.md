# Paper inventory

Status 2026-11-13. Inventory of the 27 PDF files in the three literature archives. Findings here are **inputs for review**, not approved conclusions.

## How to read this document

**Markers**

| Marker | Meaning |
|---|---|
| [E] | Explicit statement by the paper's authors, with page or section |
| [I] | Interpretation made in this review; not a claim of the paper |
| Not stated | The paper does not give the information (as far as the parts read show) |
| Not extracted | The relevant part of the paper was not read |

**Read depth**

| Depth | Meaning |
|---|---|
| Full | Whole body read |
| Partial | Abstract, contributions, dataset/evaluation passages, limitations or threats, and conclusion read; other sections located by keyword |
| Skim | Abstract, section headings and conclusion only |

Text was extracted with `pdftotext` and read page by page. Page numbers are PDF page numbers (page 1 = first page of the file), not journal page numbers. Tables and figures were read only as far as the text extraction preserved them; numbers taken from tables should be re-checked against the PDF before they are quoted in a paper.

## 1. Archives

All three archives are in `papers/` (ignored by git through the `*.zip` rule). They were opened read-only and are unchanged.

| ID | File | Size (bytes) | Files | SHA-256 |
|---|---|---|---|---|
| A1 | `bulk-download.zip` | 7,524,824 | 7 PDF | `68403bfeaab11fb7fc9d6ee13f52519477bca6c3453dbc8a511998f3e727d810` |
| A2 | `bulk-download (1).zip` | 5,948,656 | 10 PDF | `5cca53043fb8c343be6a2971ca7b8807e2630a727e362634316c19f8ad9ff219` |
| A3 | `bulk-download (2).zip` | 15,249,443 | 10 PDF | `48a7e59acf0ab3b3b2bdcc6ee52781951f28511aca79a68d7c081e180bf88ad6` |

Safety checks on the directory listings before extraction: every entry is a `.pdf` at the archive root; no absolute paths, no `..` components, no drive letters; no encrypted entries; compression ratio 1.00 for every entry (stored PDFs); largest entry 5,321,860 bytes; `unzip -t` reports no errors. All 27 files begin with the `%PDF-` signature and all 27 were parsed to text without errors. Nothing in the archives was executed. No scripts, binaries, datasets or supplementary documents are present.

The download footers show the PDFs were retrieved from IEEE Xplore on 2026-10-06.

## 2. Master list

Relevance is relative to the project's question (reliability of remediation recommendations for risky dependencies).

| ID | Archive | Short title | Authors | Year | Venue | DOI / URL | Read depth | Relevance |
|---|---|---|---|---|---|---|---|---|
| P001 | A1 | LLM and knowledge-graph escalation engine for robotics root-cause analysis | Mallala, Sharma | 2026 | CONIT (IEEE) | 10.1109/CONIT69683.2026.11621839 | Partial | Low (other domain) |
| P002 | A1 | Beyond Correctness: hallucination impact in AI-assisted workflows | Gupta, Vanteru, Kanmanth Reddy, Sunkireddy | 2026 | ICIETSD (IEEE) | 10.1109/ICIETSD68684.2026.11584879 | Full | Medium-low |
| P003 | A1 | Beyond Functional Correctness: hallucinations in LLM-generated code | Liu F., Liu Y., Shi, Yang, Zhang, Lian, Li, Ma | 2026 | IEEE Transactions on Software Engineering 52(3) | Not printed in the extracted text | Partial | Medium |
| P004 | A1 | CHASE: LLM agents for dissecting malicious PyPI packages | Toda, Mori | 2025 | AIware (IEEE/ACM) | 10.1109/AIware69974.2025.00008 | Full | **High** |
| P005 | A1 | Leveraging LLMs to detect npm malicious packages (SocketAI) | Zahan, Burckhardt, Lysenko, Aboukhadijeh, Williams | 2025 | ICSE | 10.1109/ICSE55347.2025.00146 | Partial | High |
| P006 | A1 | LLM-based code documentation generation and multi-judge evaluation | Ghrab, Dhieb, Khenissi, Abdeljaoued-Tej | 2025 | ICAHS (IEEE) | 10.1109/ICAHS66950.2025.11553031 | Partial | Low (other task) |
| P007 | A1 | Security-related code hallucinations in LLMs: systematic literature review | Daoud | 2026 | ISSATK (IEEE) | 10.1109/ISSATK69667.2026.11566869 | Full | **High** (secondary source) |
| P008 | A2 | Supply-chain risk assessment for power-system software with triangular fuzzy entropy | Zheng, Zhi, Dai, Meng | 2025 | AECSPE (IEEE) | 10.1109/AECSPE66597.2025.00095 | Skim | Low |
| P009 | A2 | Multi-level supply-chain defence system for cloud-native and HPC | Wu | 2025 | FIT (IEEE) | 10.1109/FIT67061.2025.11333619 | Skim | Low |
| P010 | A2 | A Viewpoint on Software Supply Chain Security: Are We Getting Lost in Translation? | Melara, Torres-Arias | 2023 | IEEE Security & Privacy (magazine) | 10.1109/MSEC.2023.3316568 | Partial | Medium-low |
| P011 | A2 | Analysis of supply chain attacks in open-source software and mitigation strategies (XZ Utils) | Merigala, Kumar, Gujjarlapudi, Gupta, Satish Kumar | 2024 | C2I6 (IEEE) | 10.1109/C2I663243.2024.10895136 | Partial | Low |
| P012 | A2 | Assessing software supply chain risk using public data | Benthall | **Not printed** | **Not printed** (IEEE Xplore) | Not printed | Partial | Low |
| P013 | A2 | ESPR: an Ethereum-sourced package registry | Zhu and nine co-authors | 2024 | IEEE MIT URTC | 10.1109/URTC65039.2024.10937562 | Skim | Low |
| P014 | A2 | Investigating novel approaches to defend software supply chain attacks | Hossain Faruk, Tasnim, Shahriar, Valero, Rahman, Wu | 2022 | ISSREW | 10.1109/ISSREW55968.2022.00081 | Skim | Low |
| P015 | A2 | Supply-chain security assurance mechanism based on blockchain | Zhu L. | 2024 | ISPCEM (IEEE) | 10.1109/ISPCEM64498.2024.00166 | Skim | Low |
| P016 | A2 | Blockchain smart contracts in software supply chain management | Xu, You, Xiao | 2022 | ACCC (IEEE) | 10.1109/ACCC58361.2022.00020 | Skim | Low |
| P017 | A2 | Software supply chain risk assessment framework (doctoral proposal) | Zahan | 2023 | ICSE-Companion | 10.1109/ICSE-Companion58688.2023.00068 | Full | Medium |
| P018 | A3 | A large-scale analysis of semantic versioning in npm | Pinckney, Cassano, Guha, Bell | 2023 | MSR | 10.1109/MSR59073.2023.00073 | Partial | Medium |
| P019 | A3 | A perspective view of Node Security Shield | Sangeetha G and five co-authors | 2025 | MPCON (IEEE) | 10.1109/MPCON66082.2025.11256676 | Skim | Low |
| P020 | A3 | Broken Trust in Open-Source Ecosystems: third-party packages in npm and PyPI | Lahouifi, Korchiyne, Hadi | 2025 | ICOA (IEEE) | 10.1109/ICOA66896.2025.11236532 | Full | **High** (same data sources) |
| P021 | A3 | Duplicate of P005 (same paper; file differs by 5 bytes) | — | — | — | — | — | — |
| P022 | A3 | Maldet: malicious npm package detector | Zhang, Qu, Ying, Wang | 2024 | TrustCom | 10.1109/TrustCom63139.2024.00269 | Partial | Medium |
| P023 | A3 | MalPacDetector: an LLM-based malicious npm package detector | Wang J., Li, Qu, Zou, Xu S., Xu Z., Wang Z., Jin | 2025 | IEEE Transactions on Information Forensics and Security, vol. 20 | Not printed in the extracted text | Partial | Medium-high |
| P024 | A3 | Impact of security vulnerabilities in the npm dependency network | Decan, Mens, Constantinou | 2018 | MSR | 10.1145/3196398.3196401 | Partial | Medium-high |
| P025 | A3 | Practical automated detection of malicious npm packages (Amalfi) | Sejfia, Schäfer | 2022 | ICSE | 10.1145/3510003.3510104 | Partial | Medium |
| P026 | A3 | Security issues in reusable JavaScript Actions in GitHub workflows | Onsori Delicheh, Decan, Mens | 2024 | MSR | 10.1145/3643991.3644899 | Partial | Medium-low |
| P027 | A3 | SpiderScan: malicious npm packages via graph-based behaviour modelling | Huang and eight co-authors | 2024 | ASE | 10.1145/3691620.3695492 | Partial | Medium-high |

**Counts.** 27 files, 26 distinct papers. All are research or viewpoint papers; none is a dataset, script or supplementary file. Overlap with the 28 sources in `../LITERATURE_REVIEW.md`: one paper (P005 = M5 there).

**Bibliographic gaps to close before citing.** P012 (venue and year), P003 and P023 (DOI), full author lists of P013, P019 and P027.

**What the archives do not contain.** No paper in the archives is primarily about package hallucination measurement, slopsquatting, typosquatting detection, dependency confusion, automated dependency updating, or evaluation of LLM-generated remediation. Those topics are covered only by the externally verified sources in `../LITERATURE_REVIEW.md` and in `NOVELTY_ASSESSMENT.md` §4. Absence from these archives says nothing about the wider literature.

---

## 3. Part A: papers relevant to the project (full 17-field entries)

### P002. Gupta et al. (2026): Beyond Correctness: Measuring Hallucination Impact in AI-Assisted Development Workflows

| Field | Detail |
|---|---|
| Authors | Shubham Gupta, Kusumakumari Vanteru, Prathyusha Kanmanth Reddy, Shashidhar Sunkireddy |
| Venue, year | 2026 International Conference on Innovations in Emerging Technologies for Sustainable Development (ICIETSD), IEEE. DOI 10.1109/ICIETSD68684.2026.11584879 |
| Archive, format | A1, PDF, 6 pages. Read depth: **full text** |
| Relevance | Medium-low (names nonexistent libraries as a hallucination class; all results are synthetic) |

1. **Research problem.** [E] The downstream effect of hallucinations (fabricated APIs, incorrect parameters, nonexistent libraries) on productivity, code quality and technical debt in "vibe coding" (p1, abstract and §I).
2. **Motivation.** [E] Hallucinations are mostly treated "as a dichotomous correctness problem, and not as a workflow-level phenomenon" (p1, §I).
3. **Objectives.** [E] A theory of hallucination effect, a taxonomy, a measurement model and illustrative results (p1, contribution list).
4. **Research question.** [E] "How do particular types of hallucinations in AI-assisted code generation influence the productivity of developers, code quality, and technical debt in vibe coding workflows?" (p1).
5. **Threat model / assumptions.** [E] Developers accept suggestions with little inspection; nonexistent libraries bring "dependency errors, supply-chain risk" (p2, §III.C, Table I).
6. **Dataset.** [E] A **synthetic** dataset of vibe-coding sessions "conditioned on frequencies and failure modes reported in the literature" (p3, §V.C).
7. **Size and composition.** [E] "Hundreds" of tasks; no exact count (p3). Hallucination shares are set by the authors: fabricated APIs 35%, incorrect parameters 40%, nonexistent libraries 25% (p4, Table II).
8. **Methodology.** [E] Within-subject design with a baseline and a hallucination-rich condition; "each participant (or simulated agent in a synthetic study)" (p3, §V.A).
9. **Model / architecture.** Not stated. No LLM, tool or model version is named.
10. **Baselines.** [E] "Baseline AI-assisted" versus "Hallucination-rich AI" (p4, Tables III–V).
11. **Metrics.** [E] Task time, iterations, context switches, test pass rate, defect density, API-misuse count, rework ratio, new dependencies, latent defect risk (p2–p3, §IV).
12. **Findings.** [E] Presented as "synthetic" and "illustrative": median task time 30 → 26 min, iterations 4 → 6, test pass rate 92% → 84%, rework ratio 18% → 31%, new dependencies per 10 tasks 1.2 → 2.6 (p4, Tables III–V).
13. **Ablations.** None.
14. **Limitations acknowledged.** [E] Results are "synthetic, calibrated"; no access to real usage logs (p3–p4).
15. **Future work.** [E] "Large-scale, real-world experiments on a variety of teams and stacks" (p5, §IX).
16. **Reproducibility.** Not stated. No data, code or generation procedure is released.
17. **Contribution claimed.** [E] An impact-sensitive evaluation framework and taxonomy (p5, §IX).

**Assessment [I].** The numbers are author-chosen illustrations, not measurements; they must not be cited as empirical evidence. The paper is usable only as a statement that the workflow-level cost of nonexistent-library hallucinations has not been measured on real data. Its mitigation list mentions grounding generation in "package registries" and demanding "citations" (p5, §VIII) without evaluating either.

### P003. Liu et al. (2026): Beyond Functional Correctness: Exploring Hallucinations in LLM-Generated Code

| Field | Detail |
|---|---|
| Authors | Fang Liu, Yang Liu, Lin Shi, Zhen Yang, Li Zhang, Xiaoli Lian, Zhongqi Li, Yuchi Ma |
| Venue, year | IEEE Transactions on Software Engineering, vol. 52, no. 3, March 2026, from p. 1037. Replication package: https://github.com/Lorien1128/code_hallucination |
| Archive, format | A1, PDF, 19 pages. Read depth: **partial** (p1–p2, p5–p8 passages, p14–p17) |
| Relevance | Medium (taxonomy of code hallucinations; small mitigation experiment) |

1. **Research problem.** [E] Types, causes and impacts of hallucinations in LLM-generated code are not comprehensively understood (p1, abstract).
2. **Motivation.** [E] Hallucinations "may undermine the correctness, performance, maintenance, and even security of the developed software" (p2).
3. **Objectives.** [E] Build a taxonomy, measure its distribution, analyse causes and impacts, explore training-free mitigation (p2).
4. **Research questions.** [E] RQ1 distribution of code hallucinations; RQ2 causes; RQ3 impact (p2).
5. **Assumptions.** [E] Code hallucination is "an explicit semantic conflict between the generated code and established facts"; implicit conflicts and plain syntax errors are excluded (p2 and §II).
6. **Dataset.** [E] Code generated on HumanEval (164 Python tasks) and CoderEval (230 Python and 230 Java functions) (p5–p6).
7. **Size.** [E] 3,120 samples (820 + 1,150 + 1,150) (p6).
8. **Methodology.** [E] Thematic analysis with open coding: pilot on 500 samples to build a codebook, remaining samples labelled by ten annotators, disagreements resolved in discussion (p6–p7).
9. **Models.** [E] Several open and closed code LLMs, including DeepSeek-Coder 1.3B and 7B, CodeLlama-7B and DeepSeek-R1 (§IV–V); the exact list is in the paper's Table I (not re-read here).
10. **Baselines.** [E] For mitigation: original prompt versus Self-Refine, Chain-of-Thought and RAG (p14–p16).
11. **Metrics.** [E] Share of hallucination types; pass@1; counts of hallucinatory samples (p16, Table IV).
12. **Findings.** [E] Three primary categories and twelve types. Knowledge hallucinations are 34.90% of hallucinations, of which Library/Project knowledge 25.99% (§IV.B). Requirement Conflicting is the most frequent category (p2). RAG with repository context on CoderEval (Python), DeepSeek-Coder-1.3B, 144 samples: hallucinatory samples 43.06% → 20.14%; Knowledge hallucinations 21 → 9; pass@1 14.78 → 26.52 (p16, Table IV). Self-Refine and CoT on HumanEval lowered pass@1 (61.59 → 54.27 and 51.83); the loss came "mainly ... from samples that were originally free of hallucinations" (p15).
13. **Ablations.** None beyond the three strategies.
14. **Limitations acknowledged.** [E] Python and Java only; manual labelling "is somewhat subjective"; prompt and decoding choices (p17, §VI.C). Prompt-enhancement effectiveness "still heavily relies on ... the accurate extraction of relevant real-world knowledge" (p16).
15. **Future work.** [E] Automated hallucination detection (LLM judges, ensembles, critic models); "leveraging external tools for knowledge retrieval and fact-checking"; other code tasks such as program repair (p16–p17).
16. **Reproducibility.** [E] Replication package public (p1, p18).
17. **Contribution claimed.** [E] The first comprehensive hallucination-centred analysis of LLM-generated code and a taxonomy (p5).

**Assessment [I].** The paper studies API- and project-level knowledge errors, not package names; it cites the package-hallucination work only as a "very specific type" (p5). Two results transfer: retrieval roughly halves hallucinations but leaves a residual (9 of 144), and a mitigation can damage outputs that were correct (the pass@1 loss), which is the reason to measure a verifier's wrong rejections and coverage cost and not only what it removes. The mitigation experiment uses one small model and one run.

### P004. Toda and Mori (2025): CHASE: LLM Agents for Dissecting Malicious PyPI Packages

| Field | Detail |
|---|---|
| Authors | Takaaki Toda, Tatsuya Mori |
| Venue, year | 2025 2nd IEEE/ACM International Conference on AI-powered Software (AIware). DOI 10.1109/AIware69974.2025.00008. Project page: https://t0d4.github.io/CHASE-AIware25/ |
| Archive, format | A1, PDF, 10 pages. Read depth: **full text** (body p1–p8; appendix not read) |
| Relevance | **High** (multi-agent LLM system for package security that uses deterministic tools to offset LLM unreliability) |

1. **Research problem.** [E] LLM-based malicious-package analysis suffers from "hallucination and context confusion, which can lead to missed detections or false alarms" (p1, abstract).
2. **Motivation.** [E] Registry operators need very low false-positive rates; binary detectors do not reveal attack chains, objectives or indicators of compromise (p1 §I; p3 §II.C).
3. **Objectives.** [E] Design a "high-reliability multi-agent architecture" and evaluate detection and report quality (p2, contribution list).
4. **Research questions.** Not stated as RQs.
5. **Threat model.** [E] Malicious PyPI packages that run payloads at install (`setup.py`) or import (`__init__.py`), with multi-stage, encrypted or obfuscated payloads (p2 §II.B; p5 §V.A).
6. **Dataset.** [E] Malicious: `pypi_malregistry` (commit starting `153aba56`). Benign: randomly selected packages newly published on PyPI, July–September 2025 (p5, §V.A).
7. **Size.** [E] 3,000 packages: 500 malicious, 2,500 benign (p4–p5).
8. **Methodology.** [E] Supervisor–worker agents with a Plan-and-Execute workflow, state-based communication instead of message history, and a budget-aware planner (p3–p4, §III).
9. **Model / architecture.** [E] Supervisor Qwen3:32B; workers Qwen3:8B (Deobfuscator, Web Researcher); Gemma3:4B for JSON conversion; local inference through SGLang on one NVIDIA H100 (p4 §IV.A; p5). Deterministic tools: Fernet decryption, base64 decoding, sandboxed code execution (1-minute limit), URL fetch, web search, and a composite VirusTotal tool that keeps hash strings away from the LLM (p4 §IV.B, Fig. 2).
10. **Baselines.** [E] MalGuard (Random Forest) and GuardDog (p6, §V.C.2); a single-agent Plan-and-Execute baseline with the same tools (p7, §V.E).
11. **Metrics.** [E] Precision, recall (timeouts counted against recall), F1, false-positive rate, analysis time; five-dimension Likert survey (accuracy, completeness, clarity, actionability, reliability) (p6–p7).
12. **Findings.** [E] Recall@1 0.984, precision 0.996, false-positive rate 0.08% (2 of 2,475), median 272.68 s per package (p6, Table I). MalGuard: precision 0.972, recall 0.922; GuardDog: precision 0.675, recall 0.854 (p6, Table II). Survey with **three** professionals on **three** reports: benign-report averages 2.9–4.1, malicious-report averages 3.7–4.3 (p7, Tables IV–VI). The system "tended to over-assess risks in benign code"; one participant found the recommendations "unclear who these are for" (p7).
13. **Ablation.** [E] Single-agent versus multi-agent on four packages, reported qualitatively (p7 §V.E; p8 Table VII).
14. **Limitations acknowledged.** [E] Only `setup.py`, `__init__.py` and files imported by it are analysed, covering 87.6% of malicious packages per the cited source; only two worker types; 820 timeouts on the first trial; the two false positives came from conflating "Insecurity" and "Maliciousness" (p6–p8).
15. **Future work.** [E] More workers (dynamic analyser, source retriever), other registries such as npm, parallel workers, adversarial testing, real-time deployment (p8).
16. **Reproducibility.** [E] Project page given; malicious data from a public repository at a stated commit. Code availability is not stated in the body.
17. **Contribution claimed.** [E] "Reliability in LLM-based security analysis emerges not from improving individual model capabilities but from architecting systems that compensate for LLM weaknesses" (p1).

**Assessment [I].** CHASE is direct prior art for two ideas this project might be tempted to claim: (a) a multi-agent LLM pipeline for package security, and (b) pairing an LLM with deterministic tools to raise reliability. Differences: its deterministic tools sit *inside* the generation loop and supply inputs; they do not independently check the final report. The final verdict and the report's recommendations are not verified by any non-LLM mechanism, and the only quality check of the report text is a three-person survey. It works on package code (which this project may not open), covers the malicious family only, and produces an analysis report, not a remediation for a consuming project. The observed "insecure versus malicious" conflation is independent support for keeping label families separate.

### P005 (and duplicate P021). Zahan et al. (2025): Leveraging Large Language Models to Detect npm Malicious Packages

| Field | Detail |
|---|---|
| Authors | Nusrat Zahan, Philipp Burckhardt, Mikola Lysenko, Feross Aboukhadijeh, Laurie Williams |
| Venue, year | 2025 IEEE/ACM 47th International Conference on Software Engineering (ICSE). DOI 10.1109/ICSE55347.2025.00146 |
| Archive, format | A1 and A3, PDF, 13 pages. Read depth: **partial** (p1–p4 passages, p6–p11) |
| Relevance | High (LLM detection with a deterministic baseline and pre-screener) |

1. **Research problem.** [E] Existing malicious-code detection needs several tools and has high misclassification rates (p1, abstract).
2. **Motivation.** [E] Challenges include missed malicious code, "validation due to the lack of ground truth", and registries that "only acknowledge receipt of the reports without confirming the presence of malicious code" (p1).
3. **Objectives.** [E] "Aid security analysts in detecting malicious packages by empirically studying the effectiveness of LLMs" (p1).
4. **Research questions.** [E] RQ1 performance of LLMs versus static analysis (p6); RQ2 effect of a static-analysis pre-screener on files and cost (p7); RQ3 which malicious packages are detected or missed (p8).
5. **Threat model.** Malicious code in npm package files: exfiltration, reverse shells, backdoors, typosquatting, dependency confusion (p8).
6. **Dataset.** [E] MalwareBench (3,523 malicious and 10,691 neutral npm packages); a cost-bounded subset is used (p2).
7. **Size.** [E] 5,115 packages: 2,180 malicious, 2,935 neutral; 18,754 unique files (p1, p7).
8. **Methodology.** [E] "SocketAI" workflow: iterative self-refinement, LLM-as-a-Judge scoring and zero-shot role-play chain-of-thought prompts, with a JSON report containing confidence, obfuscation, malware and security-risk scores (p1, p3–p4).
9. **Models.** [E] GPT-3 and GPT-4 (p1).
10. **Baselines.** [E] 39 CodeQL queries from prior work (p6).
11. **Metrics.** [E] Precision, recall, F1, false positives, number of files analysed, cost in dollars (p6–p7).
12. **Findings.** [E] CodeQL precision 0.75, F1 0.85; GPT-3 precision 0.91, F1 0.94; GPT-4 precision 0.99, F1 0.97, recall 0.95 with 3 false positives; "GPT-4 has the highest false negative rate" (p7). Pre-screening reduces files by 77.9% and cost by 60.9% (GPT-3) and 76.1% (GPT-4) (p11). Self-refinement improved performance by about 20% over one-step generation (p4).
13. **Ablations.** [E] With and without the pre-screener (p7).
14. **Limitations acknowledged.** [E] Mode collapse and hallucination persist, "resulting in a lack of diversity, ambiguity, and noise in the output"; large files, intraprocedural analysis and prompt injection (p10–p11). File-level ground truth did not exist and was built by manual review of model reports (p8).
15. **Future work.** [E] Compare with ML/DL models; other LLMs; further work on mode collapse and prompt injection (p10–p11).
16. **Reproducibility.** Benchmark from prior work; prompts printed in the paper (p3). Artefact availability not extracted.
17. **Contribution claimed.** [E] "The first to propose an end-to-end LLM-based workflow for malicious code review" (p10).

**Assessment [I].** Prior art for "LLM versus deterministic baseline" and for a deterministic stage placed before an LLM. The judging step is the same model family scoring its own output, so it is not an independent check. One challenge the prompt design addresses is "differentiation between malware cases and security vulnerabilities" (p4), again the family-separation problem. No remediation is produced.

### P007. Daoud (2026): Security-related code hallucinations in Large Language Models: A Systematic Literature Review

| Field | Detail |
|---|---|
| Authors | Salma Daoud |
| Venue, year | 2026 International Symposium of Systems, Advanced Technologies and Knowledge (ISSATK), IEEE. DOI 10.1109/ISSATK69667.2026.11566869 |
| Archive, format | A1, PDF, 6 pages. Read depth: **full text** |
| Relevance | **High** as a map of the hallucination literature; secondary source |

1. **Research problem.** [E] Security implications of hallucinations in LLM-generated code are "fragmented across various studies" (p1, §I).
2. **Motivation.** [E] Hallucinated code "appears correct and functional", so developers over-trust it (p1).
3. **Objectives.** [E] Consolidate 2024–2025 research on types, frequency, evaluation methods, mitigations and supply-chain implications (p3, §III.A).
4. **Research questions.** [E] Five (rq1–rq5): types with security implications; frequency and conditions; evaluation methods and benchmarks; mitigation strategies; implications for supply chains and workflows (p3, §III.A).
5. **Assumptions.** [E] "Security-related hallucinations" are hallucinated code elements that "directly introduce security vulnerabilities or exploitable conditions" (p1, §II).
6. **Data sources.** [E] IEEE Xplore, ACM Digital Library, Google Scholar, arXiv; January 2024 to December 2025; PRISMA 2020 (p3, §III.A–B).
7. **Size.** [E] 52 studies found, 22 after title and abstract screening, **16 included** (p3, §III.D).
8. **Methodology.** [E] Systematic literature review with thematic synthesis (p3, §III.E).
9. **Model / architecture.** Not applicable.
10. **Baselines.** Not applicable.
11. **Metrics.** Not applicable (reports metrics of the reviewed studies, such as the Package Hallucination Rate, p4 §IV.D.b).
12. **Findings.** [E] Five hallucination types: dependency/package, API/documentation, security logic, contextual, implicit security assumptions (p3–p4, §IV.B). Package hallucination rates "approximately 5% in state-of-the-art proprietary models to over 20% in open-source code models" (p3, attributed to Krishna et al.). Mitigations fall into four groups: grounding and retrieval, feedback-driven refinement, validation and tooling, prompt-level controls (p4–p5, §IV.E). "Package-existence validation is a first-line defense" (p5). "No single mitigation is sufficient across all hallucination types" (p5, §IV.F). Table I maps package hallucinations to "package existence validation / dependency allowlists / registry-level controls / CI-based dependency checks" (p6).
13. **Ablations.** Not applicable.
14. **Limitations acknowledged.** [E] The reviewed evaluation landscape is "fragmented"; "None of the frameworks measure the full lifecycle impact of security-related hallucinations — from generation to deployment and potential exploitation" (p5, §V). The review states no threats to its own validity. [I]
15. **Future work.** [E] (1) Standardised security-aware hallucination benchmarks; (2) detection and mitigation "more tightly integrated into LLM architectures and development tooling rather than treated as external safeguards"; (3) human-centred studies of developer trust (p5–p6, §VI).
16. **Reproducibility.** The list of 16 included studies is not given as a table; the screening is single-author. [I]
17. **Contribution claimed.** [E] A "hallucination-centric perspective" mapping hallucination types to impacts, benchmarks and mitigations (p2–p3).

**Assessment [I].** Three points matter for this project. (1) The review treats dependency validation as an existence check; nowhere does it discuss a hallucinated or mistyped name that resolves to an *existing* risky package, or what replaces a rejected dependency. (2) It reports that "retrieval-based grounding reduce[s] hallucination frequency but remain[s] insufficient" (p5), so grounding is established and its insufficiency is already stated. (3) It cites static-analysis-driven patching (Alrashedy et al.) as post-generation remediation of *code* flaws; no cited work remediates a *dependency*. These are statements about the 16 studies it reviewed, not about the whole literature. The attributions to Krishna et al. and others are second-hand and were not checked against the originals here.

### P010. Melara and Torres-Arias (2023): A Viewpoint on Software Supply Chain Security: Are We Getting Lost in Translation?

| Field | Detail |
|---|---|
| Authors | Marcela S. Melara, Santiago Torres-Arias |
| Venue, year | IEEE Security & Privacy (magazine), November/December 2023. DOI 10.1109/MSEC.2023.3316568 |
| Archive, format | A2, PDF, 4 pages. Read depth: **partial** (p1–p3) |
| Relevance | Medium-low (terminology argument) |

1–4. **Problem, motivation, objective, RQs.** [E] Adoption problems in supply-chain security "are largely caused by the language we use to describe risk and defenses" (p1). No research questions.
5. **Assumptions.** [E] Government, industry and academic definitions of a supply chain attack "only describe the outcomes" and not "the types of vulnerabilities they exploit, or the risks these pose" (p2–p3).
6–11. **Data, method, model, baselines, metrics.** None; viewpoint article.
12. **Findings.** [E] "Vulnerable dependencies that were exploited (like Log4j), social engineering-based vectors (like typosquatting), and compromised credentials ... are all very different in nature, but they all fall under the umbrella term 'supply chain attack'" (p3).
13–16. **Ablation, limitations, future work, reproducibility.** Not applicable or not extracted (p4 not read).
17. **Contribution.** A call for shared language to classify threats and risks (p3).

**Assessment [I].** Citable support, from a magazine viewpoint, for keeping risk families separate. Not empirical evidence.

### P017. Zahan (2023): Software Supply Chain Risk Assessment Framework

| Field | Detail |
|---|---|
| Authors | Nusrat Zahan |
| Venue, year | 2023 IEEE/ACM 45th International Conference on Software Engineering: Companion Proceedings (ICSE-Companion), doctoral research proposal. DOI 10.1109/ICSE-Companion58688.2023.00068 |
| Archive, format | A2, PDF, 5 pages. Read depth: **full text** (p1–p4) |
| Relevance | Medium (dependency-selection risk signals; remediation-time metrics) |

1. **Research problem.** [E] Practitioners "want to know how to detect the implementation of package security practices and the security risk so they can make informed decisions to select dependencies" (p1, abstract).
2. **Motivation.** [E] Guidelines list many practices but "challenges arise in validating whether these practices improve security"; detection studies are reactive, and "any ad-hoc solution is not enough to prevent an attack that we have not yet witnessed" (p2, §II).
3. **Objectives.** [E] Identify and evaluate "actionable security metrics to detect risky components in the dependency graph" (p1).
4. **Research questions.** [E] RQ1 which security practices to adopt; RQ2 how metrics can detect weak links; RQ3 how automatically detectable metrics serve as evidence of practice use, including RQ3.3 on how mean time to remediate relates to practices "for malicious and vulnerable packages" (p1).
5. **Assumptions.** [E] Attackers exploit observable "weak link signals" in package and maintainer metadata (p3, §III.B).
6. **Data.** [E] OpenSSF Scorecard results for npm and PyPI; npm registry metadata collected since January 2022; a survey answered by 470 npm package developers (p2–p3).
7. **Size.** [E] 2,818 maintainer email addresses on expired domains, allowing takeover of 8,494 packages; 94% of malicious packages contain install scripts; 58% of npm packages unmaintained; 4,743 maintainers own 52% of 1.6M packages (p3).
8. **Methodology.** [E] Empirical metric evaluation and regression of practices against vulnerability counts; proposed longitudinal registry study (p2–p4).
9. **Model.** Regression models (unspecified in this proposal).
10. **Baselines.** Not stated.
11. **Metrics.** [E] Vulnerability count, mean time to remediate (MTTR), median time to update (MTTU), cumulative days open normalised (p4, §IV.C).
12. **Findings (prior work summarised).** [E] Six weak-link signals: expired email domain, install scripts, unmaintained packages, too many maintainers, too many contributors, overloaded maintainers (p3). "Packages with increased good security practices also had increased reported vulnerability counts, demonstrating the need for confounding variable control" (p2).
13. **Ablations.** None.
14. **Limitations acknowledged.** [E] "The npm repository removes malicious packages from the registry and replaces the original metadata with dummy metadata. Thus researchers cannot extract meaningful information once a package is removed" (p3, §IV.B).
15. **Future work.** [E] The proposed framework (SSCRAF), three hypotheses H1–H3, longitudinal data collection (p3–p4).
16. **Reproducibility.** Proposal; no artefact.
17. **Contribution claimed.** [E] A risk assessment framework built from evaluated security metrics (p2).

**Assessment [I].** Two points carry over. (1) The statement that removed npm packages lose their metadata is published support for this project's rule that a current registry lookup is not historical status. (2) The finding that a higher practice score coincided with more reported vulnerabilities is a warning against treating any single score as "safe"; it supports reporting per-family findings instead of one combined score. The framework assesses a candidate dependency's risk; it does not generate or verify a remediation.

### P018. Pinckney et al. (2023): A Large Scale Analysis of Semantic Versioning in NPM

| Field | Detail |
|---|---|
| Authors | Donald Pinckney, Federico Cassano, Arjun Guha, Jonathan Bell |
| Venue, year | 2023 IEEE/ACM 20th International Conference on Mining Software Repositories (MSR). DOI 10.1109/MSR59073.2023.00073 |
| Archive, format | A3, PDF, 13 pages. Read depth: **partial** (p1–p4 passages, p10–p11) |
| Relevance | Medium (version resolution over time; what an "upgrade" recommendation means in practice) |

1. **Research problem.** [E] How developers use semantic versioning in npm and how updates, including security updates, flow downstream (p1).
2. **Motivation.** [E] npm relies on semver so that fixes reach downstream packages quickly while breaking changes need manual action (p1).
3. **Objectives.** [E] Build a dataset of every version of every npm package and analyse update flow (p1).
4. **Research questions.** [E] RQ1 do constraints allow automated updates; RQ2 do releases use semver so updates can flow; RQ3 how out of date are dependencies and how long do updates take to arrive; RQ4 what do updates change (p2).
5. **Assumptions.** Known vulnerabilities only (p11).
6. **Data.** [E] Full npm metadata and tarballs; GitHub Security Advisory database for vulnerabilities (p3–p4).
7. **Size.** Whole registry ("over two million packages", p1); exact counts not extracted.
8. **Methodology.** [E] A "time-travelling dependency resolver" that determines "which versions of each dependency would have been resolved at different times" (p1).
9. **Model.** None (measurement study).
10. **Baselines.** None.
11. **Metrics.** Shares of constraint and update types; update flow rates and delays.
12. **Findings.** [E] 81.19% of updates are released as bug updates, while 84.01% of dependency constraints accept bug and minor updates; 95.42% of sampled bug updates and 86.55% of sampled minor updates flow automatically (p10). "Minor updates introduce vulnerabilities more often than bug updates" (p10). Most security patches are bug updates, with "a disturbing set of outliers that are released as minor or even major updates" (p11).
13. **Ablations.** None.
14. **Limitations acknowledged.** [E] "We were unable to reliably scrape packages that have been deleted (for malware, copyright violations, etc.) or unpublished", so results "might not generalize to malware"; only known vulnerabilities; possible bugs in the pipeline (p11).
15. **Future work.** [E] Use the dataset to examine update contents and mechanisms to mitigate technical lag (p11).
16. **Reproducibility.** [E] "A full, reusable dataset of complete package metadata and tarball data" and tooling are released (p11, §IX).
17. **Contribution claimed.** The analysis, the resolver and the dataset (p11).

**Assessment [I].** Three uses. (1) A dated resolver is the published way to reconstruct registry state at a past time for *surviving* packages; the authors confirm it cannot recover deleted ones, which is the same limit this project identified for held-out existence checks. (2) Because security fixes sometimes arrive as minor or major versions, "upgrade to the first fixed version" is not always a small step; a recommendation can be safe by advisory range and still costly. (3) npm only.

### P020. Lahouifi et al. (2025): Broken Trust in Open-Source Ecosystems: The Risks of Third-Party Packages in npm and PyPI

| Field | Detail |
|---|---|
| Authors | Youssef Lahouifi, Redouan Korchiyne, Moulay Youssef Hadi |
| Venue, year | 2025 11th International Conference on Optimization and Applications (ICOA), IEEE. DOI 10.1109/ICOA66896.2025.11236532 |
| Archive, format | A3, PDF, 8 pages. Read depth: **full text** (p1–p7) |
| Relevance | **High for the data**: it uses the same three malicious-package sources this project holds |

1. **Research problem.** [E] A unified, current count of malicious packages in npm and PyPI together with practical mitigations "remains underexplored" (p1, §I).
2. **Motivation.** [E] Organisations lack "a centralized information bank and clear countermeasures" (p1).
3. **Objectives.** [E] Quantify prevalence, describe vulnerability types, list malware types, propose mitigations (p3, §III).
4. **Research questions.** [E] RQ1 number of malicious packages detected in 2025; RQ2 common vulnerability types in Node.js third-party modules and their severity; RQ3 common malware types and statistics; RQ4 most effective countermeasures (p3, §III.A).
5. **Threat model.** [E] Dependency confusion, typosquatting, combosquatting, vulnerabilities in legitimate packages, account compromise, malicious update (p2, §II.C, Table I). The paper keeps "vulnerabilities affecting packages" apart from intentional malicious code: "often unintentional defects" (p2).
6. **Data sources.** [E] DataDog malicious-software-packages-dataset; OpenSSF Malicious Packages repository; `lxyeternal/pypi_malregistry` (latest update 7 April 2025); HackerOne Node.js third-party module bug bounty reports (p3 §III.B; p5).
7. **Size.** [E] DataDog: 9,127 malicious packages (7,004 npm, 2,123 PyPI) (p4, §IV.A). OpenSSF: 34,356 malicious entries; npm 20,398 (59.3%), PyPI 9,271 (26.98%) (p5, Table III). MalRegistry: about 10,000 PyPI packages (p5). HackerOne: 353 resolved reports (p5, Table V).
8. **Methodology.** [E] Descriptive counting over public datasets plus case description (p3–p5). No collection date or commit is given for the DataDog and OpenSSF snapshots. [I]
9. **Model / architecture.** None.
10. **Baselines.** None.
11. **Metrics.** Counts and percentages only.
12. **Findings.** [E] OpenSSF malicious packages per year: npm 5 / 6,671 / 2,071 / 6,740 / 4,911 and PyPI – / 20 / 6,467 / 2,286 / 498 for 2021–2025 (p5, Table IV). **812 packages are shared by MalRegistry, DataDog and OSV** (p5, §IV.C). HackerOne severity: critical 16.4%, high 32.86%, medium 26.62%, low 24.07% (p5, Table V). The `aiocpa` incident: a trusted package that became malicious in versions 0.1.13 and 0.1.14 (p3, §II.E).
13. **Ablations.** None.
14. **Limitations acknowledged.** [E] The source lists "may contain false positives, where packages are erroneously flagged as malicious", and scanners and reporters "might miss certain sophisticated malware variants"; counts are "a robust estimate based on currently identifiable threats" (p4, §III.C).
15. **Future work.** [E] Obfuscation evolution; "evaluate the comparative effectiveness of automated detection tools"; "exploring developer behavior and decision-making during package installation"; threat-intelligence sharing (p7, §VI).
16. **Reproducibility.** Public sources named; no snapshot identifiers, scripts or derived data. [I]
17. **Contribution claimed.** [E] A 2025 overview with "foundational risk mitigation strategies": name reservation, namespaces, version pinning and lock files, developer verification, registry monitoring (p6, §V).

**Assessment [I].**
- The PyPI yearly counts for 2022 and 2023 (20 and 6,467) equal the counts recomputed locally from this project's OpenSSF slice (`../PROBLEM_DEFINITION.md` §1.5), which is an independent check of that slice. The 2024 and 2025 counts differ (2,286 and 498 here; 2,645 and 1,246 locally), as expected from a later snapshot.
- The 812-package three-way overlap is published support for the rule that these sources are not independent confirmations.
- The paper's own definitions of typosquatting and combosquatting appear swapped (p2: "typosquatting ... combining legitimate names with extra words", "combosquatting ... common misspellings"). Do not cite its definitions.
- The mitigations are advice to developers and are not evaluated. No recommendation is generated or checked for a specific flagged dependency, and nothing addresses what a developer should use *instead* of a flagged package.

### P022. Zhang et al. (2024): Maldet: An Automated Malicious npm Package Detector Based on Behavior Characteristics and Attack Vectors

| Field | Detail |
|---|---|
| Authors | Yu Zhang, Haipeng Qu, Lingyun Ying, Linghui Wang |
| Venue, year | 2024 IEEE 23rd International Conference on Trust, Security and Privacy in Computing and Communications (TrustCom). DOI 10.1109/TrustCom63139.2024.00269 |
| Archive, format | A3, PDF, 6 pages. Read depth: **partial** |
| Relevance | Medium (detection; uses name-based attack vectors as a supplementary signal) |

1. **Problem.** [E] Detect malicious npm packages (p1).
2. **Motivation.** [E] npm is the largest ecosystem and a prime target (p1).
3. **Objectives.** [E] A detector using a malicious-behaviour pattern library plus a supplementary detector to reduce false negatives (p1).
4. **Research questions.** [E] Three RQs are stated (p4); wording not extracted.
5. **Threat model.** [E] Malicious behaviours and attack vectors, including name obfuscation: typosquatting, combosquatting, altered word order (p2).
6. **Dataset.** [E] Security-vendor samples, Backstabber's Knife Collection, MalOSS, npmrank top 1,000 and top 5,000 popular packages, all as `.tgz` files (p2, Table II; p4).
7. **Size.** [E] 6,126 malicious packages in total; about half for obfuscation detection and half for model building and validation (p2).
8. **Methodology.** [E] Static obfuscation detection, 29 features, classifiers, then a second pass over packages judged benign (p1, p5).
9. **Model.** [E] Decision tree, random forest, naive Bayes, SVM (and logistic regression in Table IV) (p3, p5).
10. **Baselines.** [E] GuardDog and SAP (p6).
11. **Metrics.** Accuracy, precision, recall, F1 (p5–p6).
12. **Findings.** [E] On 2,500 packages: Maldet accuracy 0.97, precision 0.93, recall 0.93, F1 0.93; SAP 0.94 / 0.81 / 0.93 / 0.86; GuardDog 0.88 / 0.64 / 0.92 / 0.75 (p6, Table VII). The conclusion names the decision tree as best, while Table IV shows the random forest with the highest scores (p5–p6); this inconsistency is in the paper.
13. **Ablations.** Not extracted.
14. **Limitations acknowledged.** None found; the paper has no limitations or threats section.
15. **Future work.** [E] Finer classification of behaviours and attack vectors; a better supplementary detector (p6).
16. **Reproducibility.** Vendor samples are not public. Not stated otherwise.
17. **Contribution claimed.** A detector combining behaviour features and attack vectors (p6).

**Assessment [I].** Popular packages are used as the benign class without verification, the same "popular means benign" assumption this project treats as "candidate only". Detection only.

### P023. Wang et al. (2025): MalPacDetector: An LLM-Based Malicious NPM Package Detector

| Field | Detail |
|---|---|
| Authors | Jian Wang, Zhen Li, Jixiang Qu, Deqing Zou, Shouhuai Xu, Ziteng Xu, Zhenwei Wang, Hai Jin |
| Venue, year | IEEE Transactions on Information Forensics and Security, vol. 20, 2025, from p. 6279 (CC BY 4.0). Code and data: https://github.com/CGCL-codes/MalPacDetector-core |
| Archive, format | A3, PDF, 13 pages. Read depth: **partial** (p1–p4, p6 passages, p11–p12) |
| Relevance | Medium-high (LLM output filtered by a frequency threshold; dataset-quality discussion) |

1. **Problem.** [E] Existing npm malware detectors have high false positives or false negatives and rely on expert-defined features (p1).
2. **Motivation.** [E] Features should update "automatically and dynamically ... as malicious behaviors evolve" (p1).
3. **Objectives.** [E] LLM-generated features; a new dataset; comparison with existing detectors (p1–p2).
4. **Research questions.** Not extracted.
5. **Threat model.** Seven attack types in malicious npm packages (p2).
6. **Dataset.** [E] MalnpmDB, built from several public sources and manually cleaned; benign class is the most popular packages "because they have likely been scrutinized by the community" (p6).
7. **Size.** [E] 3,258 malicious and 4,051 benign packages (p2).
8. **Methodology.** [E] The LLM extracts malicious snippets and summarises behaviours over several rounds; behaviours are kept as features only above a frequency threshold, "in this way, we can avoid the problem of model hallucination, and a few wrong answers will not affect the results" (p2–p3). Features are then extracted with AST analysis and fed to classifiers (p4).
9. **Model.** An LLM for feature generation plus conventional classifiers; model name not extracted.
10. **Baselines.** [E] Existing detectors, including a machine-learning detector (p2).
11. **Metrics.** False-positive and false-negative rates.
12. **Findings.** [E] False-positive rate 1.3%, false-negative rate 7.5%; 39 previously unknown malicious packages "confirmed by the NPM security team" (p1).
13. **Ablations.** Not extracted.
14. **Limitations acknowledged.** [E] Advanced obfuscation; static only; on Python "the results are significantly less impressive"; dependence on the LLM for new malware types (p11). **Threat:** all malicious samples were used to generate features, so "the training and test sets ... cannot be guaranteed as completely independent" (p12).
15. **Future work.** [E] The limitations are left "as interesting open problems" (p12).
16. **Reproducibility.** [E] Code and dataset public (p2).
17. **Contribution claimed.** LLM-guided feature generation, the dataset, and desired characteristics of a benchmark dataset (p12).

**Assessment [I].** The authors' own leakage statement is a concrete example of the train/test dependence this project must avoid by fixing splits before any use of an LLM. Each malicious label was confirmed by two researchers (p6), a labelling standard stronger than the reporter-asserted labels in this project's malicious lists.

### P024. Decan, Mens and Constantinou (2018): On the impact of security vulnerabilities in the npm package dependency network

| Field | Detail |
|---|---|
| Authors | Alexandre Decan, Tom Mens, Eleni Constantinou |
| Venue, year | 15th International Conference on Mining Software Repositories (MSR '18). DOI 10.1145/3196398.3196401 |
| Archive, format | A3, PDF, 11 pages. Read depth: **partial** (p1–p5 passages, p7–p10) |
| Relevance | Medium-high (when an upgrade remediation is possible at all) |

1. **Problem.** [E] How vulnerabilities are discovered and fixed in npm and how they affect dependent packages (p1).
2. **Motivation.** [E] Vulnerabilities "may propagate to dependent packages" (p1).
3. **Objectives.** [E] Findings and guidelines for maintainers and tool developers (p1).
4. **Research questions.** [E] RQ0 how many packages are affected; RQ1 how long packages remain vulnerable; RQ2 when vulnerabilities are discovered; RQ3 when they are fixed; RQ4 when they are fixed in dependent packages (p1–p2).
5. **Assumptions.** Runtime dependencies only (p8).
6. **Data.** [E] Snyk.io security reports combined with release and dependency history from libraries.io (p8).
7. **Size.** [E] 399 reports, 269 packages, 6,752 affected releases, 72,470 affected dependent packages; npm with over 610k packages (p1, p10).
8. **Methodology.** [E] Survival analysis; resolution of version constraints at the time of installation (p4, p10).
9. **Model.** None.
10. **Baselines.** None.
11. **Metrics.** Time to discovery and to fix; shares of affected releases and dependents.
12. **Findings.** [E] In 75% of affected packages more than 90% of releases were affected; over 24 months to discover half of all vulnerabilities (p7). One third are fixed at or before discovery; about 15% are fixed after publication or never (p10). "**More than 40% of all package releases depending on a vulnerable package release cannot be fixed automatically by depending on a more recent release, because the imposed dependency constraints do not allow them to be installed**" (p10).
13. **Ablations.** Other time thresholds gave similar results (p7, footnote).
14. **Limitations acknowledged.** [E] Results are "a lower bound"; "the large majority of these constraints specify only an upper bound on the versions. It is difficult to say whether this effectively means that all previous releases are affected, or whether no lower bound is specified out of ignorance"; packages removed before data collection are missing (p8).
15. **Future work.** [E] Wider dependency networks, other ecosystems, analysis by CWE type (p10).
16. **Reproducibility.** Not extracted.
17. **Contribution claimed.** A precise identification of affected releases using both vulnerability and dependency constraints (p10).

**Assessment [I].** Two direct consequences for this project. (1) Advisory ranges are imprecise at the lower bound, so a check of "version outside every affected range" inherits that imprecision; the unsafe-version metric is a policy over advisory data, not ground truth. (2) A range-safe upgrade is often not installable under existing constraints, so a remediation that passes a range check is not shown to be applicable. Data are from 2018 and npm only; the present-day share is unverified.

### P025. Sejfia and Schäfer (2022): Practical Automated Detection of Malicious npm Packages (Amalfi)

| Field | Detail |
|---|---|
| Authors | Adriana Sejfia, Max Schäfer |
| Venue, year | 2022 IEEE/ACM 44th International Conference on Software Engineering (ICSE). DOI 10.1145/3510003.3510104 |
| Archive, format | A3, PDF, 12 pages. Read depth: **partial** (p1–p8 passages, p11) |
| Relevance | Medium (ML detection followed by deterministic checks that remove false positives) |

1. **Problem.** [E] The volume of npm updates makes manual review infeasible (p1).
2. **Motivation.** [E] Malicious packages tamper with or exfiltrate data from anyone who installs them (p1).
3. **Objectives.** [E] A light-weight, practical detector (p1–p3).
4. **Research questions.** [E] RQ1 practical performance on newly published packages; RQ2 accuracy; RQ3 performance (p7).
5. **Threat model.** New malicious packages and malicious updates of existing ones (p1).
6. **Dataset.** [E] npm's archive of 643 malicious package versions detected up to 29 July 2021, plus 1,147 benign versions of the same packages (p5).
7. **Size.** [E] Basic corpus 1,790 versions; live experiment on 96,287 versions published 29 July to 4 August 2021 (p1, p5–p6).
8. **Methodology.** [E] Eleven features from a syntactic scan; three classifiers; then a **reproducer** that rebuilds the package from source ("packages that are reproducible from source are not usually malicious") and a **clone detector** that hashes package contents (p1–p2, p4–p5).
9. **Model.** [E] Decision tree, naive Bayes, one-class SVM (p2).
10. **Baselines.** The three classifiers against each other.
11. **Metrics.** True and false positives after manual triage; precision and recall in cross-validation; time (p6–p7).
12. **Findings.** [E] 95 previously unknown malicious samples, all taken down by npm; false positives fall with retraining to "fewer than one in a thousand" (p1, p3, p8).
13. **Ablations.** Variants that were "unsuccessful or unnecessary" are discussed (p8).
14. **Limitations acknowledged.** [E] The corpus "contains clusters of similar malware samples resulting from copy-cat campaigns"; inspection limited to five minutes per package; the reproducer's "success rate ... is low in practice" (p5, p8).
15. **Future work.** [E] Deeper feature extraction, fuzzy clone detection, combining classifiers, other ecosystems such as PyPI (p11).
16. **Reproducibility.** The malicious corpus was provided by npm and is not public (p5).
17. **Contribution claimed.** A combination of classifier, reproducer and clone detector that works in practice (p3).

**Assessment [I].** The clearest in-archive precedent for the *architecture pattern* "probabilistic component followed by deterministic checks". The checks here verify a detection, not a recommendation. Two data statements matter: "malicious packages are taken down by npm immediately upon discovery, most known examples ... are no longer available" (p5), and the copy-cat clusters (p8), which are a reason to group near-duplicate package names when splitting or resampling.

### P026. Onsori Delicheh, Decan and Mens (2024): Quantifying Security Issues in Reusable JavaScript Actions in GitHub Workflows

| Field | Detail |
|---|---|
| Authors | Hassan Onsori Delicheh, Alexandre Decan, Tom Mens |
| Venue, year | 2024 IEEE/ACM 21st International Conference on Mining Software Repositories (MSR). DOI 10.1145/3643991.3644899 |
| Archive, format | A3, PDF, 12 pages. Read depth: **partial** (p1–p2 passages, p8–p11) |
| Relevance | Medium-low (vulnerable-dependency exposure; npm only) |

1. **Problem.** [E] Exposure of JavaScript GitHub Actions to vulnerabilities in npm dependencies and to code weaknesses (p1).
2. **Motivation.** [E] Actions are reused in many workflows, so their issues propagate (p11).
3. **Objectives.** Quantify vulnerable dependencies and code weaknesses (p11).
4. **Research questions.** [E] RQ1 reliance on npm packages; RQ2 characteristics of the dependencies; RQ3 vulnerabilities in the dependency network; RQ4 code weaknesses (p2).
5. **Assumptions.** Dependencies as declared in `package.json` and `package-lock.json` (p10).
6. **Data.** [E] JavaScript Actions and their releases, November 2019 to June 2023; vulnerability data; CodeQL security queries (p2–p4).
7. **Size.** [E] 8,107 JavaScript Actions (53% of 30,678 Actions) (p8, p11).
8. **Methodology.** Dependency-network analysis and static analysis.
9. **Model.** None.
10. **Baselines.** None.
11. **Metrics.** Shares of Actions and releases affected.
12. **Findings.** [E] 95% of the Actions depend on npm packages; over 77% of Action releases depend on at least one vulnerable npm release; indirect dependencies "are more likely to suffer from high and critical vulnerabilities"; more than 54% of Actions contain at least one code weakness (p1, p11).
13. **Ablations.** None.
14. **Limitations acknowledged.** [E] Declared dependencies may be unused ("bloated"), which "might have inflated" exposure; SCA tools "typically do not confirm whether a vulnerable dependency poses a real threat or whether the vulnerable code remains unused" (p2, p10).
15. **Future work.** [E] Docker and Composite Actions; better dependency and security monitoring tools (p8–p10).
16. **Reproducibility.** Not extracted.
17. **Contribution claimed.** Quantification of vulnerable dependencies and weaknesses in JavaScript Actions (p11).

**Assessment [I].** Supports the scope limit already adopted: a declared vulnerable dependency is not proof of exploitability, and this project does not claim reachability.

### P027. Huang et al. (2024): SpiderScan: Practical Detection of Malicious NPM Packages Based on Graph-Based Behavior Modeling and Matching

| Field | Detail |
|---|---|
| Authors | Yiheng Huang, Zhuotong Zhou, Ruisi Wang, Susheng Wu, Wen Zheng, Shulin Ke, Bihuan Chen, Shan Gao, Xin Peng |
| Venue, year | 2024 39th IEEE/ACM International Conference on Automated Software Engineering (ASE). DOI 10.1145/3691620.3695492 |
| Archive, format | A3, PDF, 13 pages. Read depth: **partial** (p1–p4, p7–p11 passages) |
| Relevance | Medium-high (has an explicit verifier stage) |

1. **Problem.** [E] Existing detectors "do not model malicious behavior in a holistic way; only consider a predefined set of sensitive APIs; and require huge manual confirmation effort due to high false positives and binary detection results" (p1).
2. **Motivation.** [E] Practical usefulness is limited by manual confirmation effort (p1–p2).
3. **Objectives.** [E] Graph-based behaviour modelling and matching, with type and location of the detected behaviour (p2).
4. **Research questions.** [E] RQ1 effectiveness; RQ2 usefulness in real-world detection; RQ3 ablation of components (p8).
5. **Threat model.** [E] Malicious behaviour at install time, import time and run time (p2).
6. **Dataset.** [E] Publicly disclosed malicious npm packages from two types of sources, and newly published npm packages monitored for three months (p2, p8).
7. **Size.** Not extracted.
8. **Methodology.** [E] Offline: malicious behaviour graphs over control flow and data dependencies. Online: script analyser (LLM judges shell commands), obfuscation detector, behaviour extraction and matching, then a **maliciousness verifier** that executes the package in a sandbox with API hooks, collects arguments and asks an LLM whether the call is malicious (p3–p4, p7 §3.6).
9. **Model.** An LLM for sensitive-API recognition, shell-command judgement and argument judgement; model name not extracted.
10. **Baselines.** [E] GuardDog, SAP, Amalfi, Cerebro (p2).
11. **Metrics.** Precision, recall, F1, false-positive rate (p9–p10).
12. **Findings.** [E] F1 92.9% on the public dataset, 8.7 to 34.4 points above the baselines; in live monitoring a false-positive rate of 38.2%, the lowest among the tools; 249 previously unknown malicious packages, all removed by npm (p2, p10).
13. **Ablations.** [E] Three ablated versions, including one without the verifier, and a prompt ablation without role, context or examples (p8–p9, Table 7).
14. **Limitations acknowledged.** [E] Four causes of false positives are analysed (p10). No separate limitations section was found.
15. **Future work.** [E] Reduce false positives; other ecosystems (p11).
16. **Reproducibility.** Not extracted.
17. **Contribution claimed.** A practical detector with holistic behaviour modelling (p11).

**Assessment [I].** The closest in-archive design to "generate, then verify": a detection is confirmed by a second stage before it is reported, and the stage is ablated. Differences from this project: the verifier's final judgement is made by an LLM, not deterministically; it verifies a *detection* and reduces false positives; it executes the package. A live false-positive rate of 38.2% for the best tool shows that even state-of-the-art detection output needs a human or a further check.

---

## 4. Part B: papers outside the project's topic (abbreviated entries)

These papers were skimmed (abstract, headings, conclusion; evaluation passages where they exist). Fields not listed were not extracted. None contains a result this project would cite as evidence; they are recorded so that every file in the archives is accounted for.

| ID | Problem [E] | Method [E] | Data and evaluation [E] | Limitations / future work [E] | Note [I] |
|---|---|---|---|---|---|
| P001 | Turning scattered robot field data into engineering escalations (p1) | Knowledge graph plus retrieval plus LLM; prompt rules require every hypothesis to "reference specific evidence elements" and to state uncertainty when evidence is missing; human review stage (p4) | **No results.** §IV "outlines an evaluation methodology"; data are proprietary (p4–p5) | Multimodal signals; continuous learning; generalisation to other sites (p5–p6) | Same design idea as evidence-cited claims, in another domain and unevaluated. Shows the idea is not new; gives no measurement |
| P006 | Automating code documentation; choosing an LLM for it (p1) | Eight LLMs generate; four LLM judges score nine weighted metrics with a hallucination penalty (p3) | One repository (PyMedPhys); top weighted scores 4.68 and 4.65 for two Gemini models (p6) | "Depends solely on automated LLM-based assessment without the inclusion of human expert review"; single project (p5–p6) | LLM-judged quality without human or deterministic validation: the kind of evaluation this project avoids |
| P008 | Quantifying supply-chain security risk for power-system software (p1) | Triangular fuzzy numbers, fuzzy entropy weights, fuzzy AHP (p1, p5) | Worked assessment; no public dataset | Expand indicators (p5) | Organisational risk scoring; no package-level content |
| P009 | Full-lifecycle supply-chain defence for cloud-native and HPC (p1) | SBOM, signing, CI/CD controls, management process (p1, p5) | Applied in one university environment; qualitative comparison table only (p5) | ML over SBOM data to predict component risk; zero-trust integration (p5) | Descriptive framework |
| P011 | Lessons from the XZ Utils backdoor (p1) | Incident analysis and a list of mitigations: code review, scanning, signatures, audits, bug bounties (p3–p4) | None | Funding and volunteer capacity limit security work (p5) | The reported incident response was rolling back to older, uncompromised versions (p3): a real case where the correct remediation of a *compromised version* is a downgrade, not an upgrade |
| P012 | Using public data for supply-chain risk (p1) | Links NVD entries to OpenSSL release history; fits the Alhazmi–Malaiya logistic model (p3) | One project (OpenSSL) (p4) | "Limited by its focus on a single case" (p4) | Venue and year are not printed in the PDF. Observes that "most vulnerabilities affecting a software version are present in it when it is first released" (p4) |
| P013 | Registry compromise and package tampering (p1) | Package metadata in Ethereum smart contracts, files on IPFS (p1) | Proof of concept; gas-cost discussion (p5) | "Still in a proof-of-concept stage" (p5) | Addresses registry integrity, not name confusion or remediation |
| P014 | Overview of supply-chain attacks and defences (p1) | Literature review (p1) | None | — | No experiment; mentions "remediation" only as a general goal (p6) |
| P015 | Supply-chain security assurance (p1) | Blockchain with a modified Byzantine fault-tolerance algorithm (p1) | Simulation only (p5) | None stated | No real data |
| P016 | Tracing components through a supply chain (p1) | Blockchain smart-contract design (p1) | Theoretical construction (p6) | Aligning contracts with the real development lifecycle (p6) | No evaluation |
| P019 | Runtime protection of Node.js applications (p1) | Review of runtime application self-protection techniques (p1) | None | Overhead, false positives, integration effort (p5) | Runtime defence; outside dependency selection |
