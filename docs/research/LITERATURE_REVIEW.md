# Literature review

Status 2026-11-13 (revised after the foundation review). First pass; not exhaustive.

A claim-by-claim audit of how each statement was verified is in `FOUNDATION_REVIEW.md` §2.

## How to read this document

**Search method.** Web searches on 2026-11-13, followed by a fetch of each paper's arXiv record, proceedings page or Crossref DOI record. Pages were read through an automated fetch-and-summarize tool, not by a human, and Springer and IEEE full texts were not accessible. Treat every "Findings" cell as needing a human check against the PDF before it is quoted in the paper.

**Verification codes**

| Code | Meaning |
|---|---|
| **B-pub** | Bibliographic data confirmed on the publisher or proceedings page, or in the Crossref DOI record |
| **B-arXiv** | Bibliographic data confirmed on the arXiv record; the venue is what the arXiv comments field states |
| **C-full** | Content taken from the full text (arXiv HTML) |
| **C-abs** | Content taken from the abstract only |
| **C-none** | Content **not** verified this session; only the bibliographic record was confirmed |

Numbers are reported as the source states them. Nothing here was reproduced by us.

---

## 1. Package hallucination in LLM-generated code

### H1. Spracklen et al. (2025)

| Field | Detail |
|---|---|
| Title | We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs |
| Authors | Joseph Spracklen, Raveen Wijewickrama, A H M Nazmus Sakib, Anindya Maiti, Bimal Viswanath, Murtuza Jadliwala |
| Venue, year | 34th USENIX Security Symposium, 2025, pp. 3687–3706 (Distinguished Paper Award) |
| URL | https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen ; arXiv:2406.10279 |
| Verification | B-pub. Model count, sample count, 5.2% / 21.7% and 205,474 are in the abstract on the USENIX page. All other numbers below come from **one** automated read of the first 100,000 characters of arXiv v3; a second read attempt failed, so they are single-read |
| Problem | How often code LLMs recommend packages that do not exist, and whether this can be reduced |
| Dataset | Prompts from Stack Overflow questions and from descriptions of the 5,000 most-downloaded PyPI and npm packages; 576,000 code samples; 16 models |
| Method | Extract package names from generated code; compare with PyPI and npm master lists dated 2024-01-10 |
| Metrics | Hallucination rate; repetition over 10 reruns; Levenshtein distance to the nearest real name; self-detection accuracy; HumanEval pass@1 |
| Findings | 19.7% of recommended packages hallucinated; 205,474 unique names; commercial models 5.2%, open-source 21.7%; 43% of hallucinations recurred in all 10 reruns; only 13.4% of hallucinated names were within 1–2 edits of a real name. Mitigations on DeepSeek / CodeLlama (baseline 16.14% / 26.28%): RAG 12.24% / 13.40%, self-refinement 13.04% / 25.51%, fine-tuning 2.66% / 10.27%; fine-tuning cut DeepSeek HumanEval pass@1 from 51.4% to 25.3% |
| Limitations | Master lists may already contain malicious names, so rates are a lower bound; few commercial models; newer models untested |
| Relevance | Establishes the hallucination problem and that most hallucinated names are **not** typos. Evaluates prevention at generation time only; it does not evaluate what to recommend once a bad dependency is found. Shows RAG helps but leaves a residual rate, which motivates a post-hoc check. |

### H2. Twist et al. (2026): source of LibHalluBench

| Field | Detail |
|---|---|
| Title | Library Hallucinations in LLM-Generated Code: A Risk Analysis Grounded in Developer Queries |
| Authors | Lukas Twist, Mark Harman, Helen Yannakoudakis, Jie M. Zhang |
| Venue, year | Proceedings of the 2026 Conference on Empirical Methods in Natural Language Processing (EMNLP 2026), pp. 1785–1812, ACL. DOI 10.18653/2026.emnlp-main.78 (Crossref record) |
| URL | arXiv:2509.22202 (v4, 2026-08-21) |
| Verification | B-pub (Crossref), C-full (one automated read of the first 100,000 characters of arXiv v4) |
| Problem | How realistic prompt variations (asking for recent or obscure libraries, misspelt or invented library names) affect library hallucination |
| Dataset | BigCodeBench seed tasks; LibHalluBench: 4,173 prompts from 321 seeds |
| Method | Seven LLMs; imports checked against PyPI as a live oracle |
| Metrics | Share of tasks with a hallucinated library; detection pipeline precision 95.8% and recall 100% on 200 manually checked responses |
| Findings | One-character misspellings trigger hallucinations in up to 26% of tasks; multi-character up to 79%; invented names accepted in up to 99%; "from 2025" prompts up to 85%. A PyPI-existence tool reduced but did not remove the problem (GPT-4o-mini: 2.49% on "from 2025", but up to 38.79% of user-mistake cases still accepted) |
| Limitations | Python-focused; finite tasks and model versions; live oracle changes over time |
| Relevance | Our evaluation-only prompt source. The tool-use result is direct evidence that an existence check alone is not sufficient. Our own data adds that 25 of its 1,049 planted names are reported-malicious PyPI packages (`PROBLEM_DEFINITION.md` §2). |

### H3. Krishna et al. (2025)

| Field | Detail |
|---|---|
| Title | Importing Phantoms: Measuring LLM Package Hallucination Vulnerabilities |
| Authors | Arjun Krishna, Erick Galinkin, Leon Derczynski, Jeffrey Martin |
| Venue, year | arXiv preprint, 2025 (arXiv:2501.19012). **No venue listed; peer-review status unknown** |
| Verification | B-arXiv, C-abs |
| Problem | Package hallucination across languages and models |
| Dataset / method | Multiple LLMs and languages (the abstract gives no sizes) |
| Metrics | Hallucination rate; relation to HumanEval score |
| Findings | Rate depends on model, language, model size and task specificity; inverse correlation with HumanEval score |
| Limitations | Not verified (abstract only) |
| Relevance | Supporting evidence for the problem. Not peer-reviewed as far as we could verify. |

### H4. Miranda-Pena et al. (2026)

| Field | Detail |
|---|---|
| Title | An Empirical Analysis of Static Analysis Methods for Detection and Mitigation of Code Library Hallucinations |
| Authors | Clarissa Miranda-Pena, Andrew Reeson, Cécile Paris, Josiah Poon, Jonathan K. Kummerfeld |
| Venue, year | Accepted at Transactions on Machine Learning Research (per arXiv comments), 2026; arXiv:2604.07755 |
| Verification | B-arXiv, C-abs |
| Problem | How much of library hallucination a deterministic static analyzer can catch |
| Dataset | Natural-language-to-code benchmarks requiring library use |
| Metrics | Share of errors and of library hallucinations detected |
| Findings | LLMs use nonexistent library features in 8.1%–40% of responses; static analysis detects 16%–70% of all errors and 14%–85% of library hallucinations; estimated upper bound 48.5%–77% |
| Limitations | Concerns library *features* (members), not only package names |
| Relevance | The closest peer-reviewed precedent for "deterministic checker over LLM output". It measures the coverage ceiling of a deterministic method, a framing we should reuse for our verifier. |

### H5. Raj and Sahu (2026)

| Field | Detail |
|---|---|
| Title | Names Can Hurt: Spotting Slopsquatting Risks Caused by Package Name Hallucinations in Local Coding LLMs |
| Authors | Akash Raj, Sargam Sahu |
| Venue, year | arXiv preprint, 2026 (arXiv:2608.23897). **No venue listed** |
| Verification | B-arXiv, C-abs (abstract read twice, the second time from the raw arXiv API record; the full text could not be read) |
| Problem | Detecting hallucinated Python package names from local LLMs, including names that are already registered |
| Dataset | 300 prompts |
| Method | Layer 1: deterministic PyPI existence check. Layer 2: Random Forest on ten name and metadata features. Retry at higher temperature, then fall back to a stronger model |
| Metrics / findings | Hallucination-free code on 76% of runs; about half of the flagged hallucinations are packages **already registered on PyPI** (low-quality lookalikes of well-known projects), caught by the classifier and not by the existence check; hallucination rate rises from 0–10% on routine prompts to 40–73% on bait prompts; about 84% of primary-model failures recur on a same-family fallback; user study n = 24 |
| Limitations | Not verified (abstract only); small prompt set |
| Relevance | Closest architectural neighbour for detection (existence check plus a second detector for registered lookalikes). Its response to a detection is regeneration, not an evidence-based recommendation, as far as the abstract shows. |

### H6. Öz (2026): dataset

| Field | Detail |
|---|---|
| Title | Package Hallucination in LLM-Generated Python Code: Data and Code |
| Author | Erin Su Öz |
| Venue, year | Zenodo dataset, v1.0, 2026. DOI 10.5281/zenodo.23962898 |
| Verification | Local `record_metadata.json` and README (MD5 verified in Session 0). **No paper located** |
| Relevance | Our only human-reviewed nonexistence labels (`PROBLEM_DEFINITION.md` §1.2). |

### H7. Li and Gao (2025)

| Field | Detail |
|---|---|
| Title | Investigating Security Implications of Automatically Generated Code on the Software Supply Chain |
| Authors | Xiaofan Li, Xing Gao |
| Venue, year | arXiv preprint, 2025 (arXiv:2509.20277). **No venue listed** |
| Verification | B-arXiv, C-abs |
| Problem | Eleven supply-chain threats in LLM-generated code, including external components and CI configuration |
| Dataset / method | 439,138 prompts; four LLMs (GPT and Llama families); a prompt-based defence ("Chain-of-Confirmation") and a middleware that warns users |
| Findings | All eleven threats occur in all tested models |
| Limitations | Not verified (abstract only) |
| Relevance | The nearest work that treats several supply-chain risks of LLM output together. Its defences are a prompt technique and warnings; the abstract does not describe evidence-cited recommendations or a separate verifier. Needs a full read before we claim a difference. |

### H8. Latendresse et al. (2024)

| Field | Detail |
|---|---|
| Title | Is ChatGPT a Good Software Librarian? An Exploratory Study on the Use of ChatGPT for Software Library Recommendations |
| Authors | Jasmine Latendresse, SayedHassan Khatoonabadi, Ahmad Abdellatif, Emad Shihab |
| Venue, year | arXiv preprint, 2024 (arXiv:2408.05128; comments: "Submitted"). **Venue unverified** |
| Verification | B-arXiv, C-abs |
| Findings | On 10,000 Stack Overflow questions with GPT-3.5 Turbo: third-party libraries used about 10% more often than by humans; 14.2% of recommended libraries have copyleft licences; 6.5% did not work out of the box |
| Relevance | Evidence that LLM library recommendations have quality problems beyond nonexistence. |

---

## 2. Typosquatting and package confusion

### T1. Vu et al. (2020)

| Field | Detail |
|---|---|
| Title | Typosquatting and Combosquatting Attacks on the Python Ecosystem |
| Authors | Duc-Ly Vu, Ivan Pashchenko, Fabio Massacci, Henrik Plate, Antonino Sabetta |
| Venue, year | 2020 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW), pp. 509–514. DOI 10.1109/EuroSPW51379.2020.00074 |
| Verification | B-pub (Crossref), **C-none** |
| Relevance | Early PyPI typosquatting study. Read before citing any finding. |

### T2. Taylor et al. (2020): "SpellBound"

| Field | Detail |
|---|---|
| Title | Defending Against Package Typosquatting |
| Authors | Matthew Taylor, Ruturaj Vaidya, Drew Davidson, Lorenzo De Carli, Vaibhav Rastogi |
| Venue, year | Network and System Security (NSS 2020), LNCS, pp. 112–131. DOI 10.1007/978-3-030-65745-1_7 |
| Verification | B-pub (Crossref), **C-none** |
| Relevance | Ecosyste.ms attributes 16 npm pairs to "spellbound-paper"; the link to this paper is our inference and is **unverified**. |

### T3. Neupane et al. (2023)

| Field | Detail |
|---|---|
| Title | Beyond Typosquatting: An In-depth Look at Package Confusion |
| Authors | Shradha Neupane, Grant Holmes, Elizabeth Wyss, Drew Davidson, Lorenzo De Carli |
| Venue, year | 32nd USENIX Security Symposium, 2023, pp. 3439–3456 |
| URL | https://www.usenix.org/conference/usenixsecurity23/presentation/neupane |
| Verification | B-pub, C-abs |
| Dataset / method | More than 1,200 documented attacks; qualitative analysis into 13 confusion mechanisms; detectors run over npm |
| Findings | Many mechanisms are semantic, not spelling-based; most flagged pairs were missed by existing tools |
| Limitations | Not verified (abstract only) |
| Relevance | Shows that edit distance (our Agent 3 v1) covers only part of package confusion. Bounds what a name-similarity baseline can claim. |

### T4. Truong et al. (2025): source of the YCTT dataset

| Field | Detail |
|---|---|
| Title | You Can't Touch This: Detecting Typosquatting Packages for Enhanced Malware Prevention in Software Supply Chains |
| Authors | Minh Tien Truong, Nils Gruschka, Luigi Lo Iacono |
| Venue, year | Network and System Security (NSS 2024), LNCS, pp. 147–166, Springer, 2025. DOI 10.1007/978-981-96-3531-3_8 |
| Verification | B-pub (Crossref), C-abs (abstract in the dataset README) |
| Dataset | 394 npm typosquats with source (406 listed); Backstabber's and MalOSS snapshots |
| Method | String-matching metrics, including an extended Damerau-Levenshtein distance; ML classifier on package features |
| Metrics / findings | Overall accuracy 98.4% on own data, 96.0% and 93.5% on two other datasets (as the abstract states) |
| Limitations | npm only; vendor-listed labels; data to early 2023 |
| Relevance | Dataset source, and a published string-metric baseline to compare Agent 3 against. |

### T5. Jiang et al. (2026): ConfuGuard

| Field | Detail |
|---|---|
| Title | ConfuGuard: Using Metadata to Detect Active and Stealthy Package Confusion Attacks Accurately and at Scale |
| Authors | Wenxin Jiang, Berk Çakar, Mikola Lysenko, James C. Davis |
| Venue, year | ICSE 2026 Research Track (confirmed on the conference programme page; proceedings DOI not obtained); arXiv:2502.20528 (v3, 2025-08-01) |
| Verification | B-arXiv, C-abs |
| Method | Package metadata used to filter benign lookalikes; seven registries; deployed at an industry partner |
| Findings | False-positive rate reduced from 80% to 28%; three to seven registries; about 14 s added latency; 630 analyst-confirmed attacks (the arXiv v3 abstract and the ICSE programme abstract agree; a search summary reported different numbers for another version) |
| Relevance | State of the art in confusion detection, and evidence that name similarity alone has a very high false-positive rate. We have no metadata, so we cannot compete on detection and should not claim to. |

---

## 3. Malicious package detection and supply-chain attacks

### M1. Ohm et al. (2020)

| Field | Detail |
|---|---|
| Title | Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks |
| Authors | Marc Ohm, Henrik Plate, Arnold Sykosch, Michael Meier |
| Venue, year | Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA 2020), LNCS, pp. 23–43. DOI 10.1007/978-3-030-52683-2_2 |
| Verification | B-pub (Crossref), **C-none** |
| Relevance | Origin of one of the YCTT feature snapshots; its licence terms apply to that snapshot. |

### M2. Duan et al. (2021)

| Field | Detail |
|---|---|
| Title | Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages |
| Authors | Ruian Duan, Omar Alrawi, Ranjita Pai Kasturi, Ryan Elder, Brendan Saltaformaggio, Wenke Lee |
| Venue, year | NDSS Symposium 2021 (per arXiv comments); arXiv:2002.01139 |
| Verification | B-arXiv, C-abs |
| Method / findings | Metadata, static and dynamic analysis of registries; 339 new malicious packages reported, 278 confirmed by maintainers |
| Relevance | Source of the MalOSS collection. Program-analysis detection, which is outside our scope. |

### M3. Guo et al. (2023)

| Field | Detail |
|---|---|
| Title | An Empirical Study of Malicious Code In PyPI Ecosystem |
| Authors | Wenbo Guo, Zhengzi Xu, Chengwei Liu, Cheng Huang, Yong Fang, Yang Liu |
| Venue, year | 38th IEEE/ACM International Conference on Automated Software Engineering (ASE 2023), per arXiv comments; arXiv:2309.11021 |
| Verification | B-arXiv, C-abs |
| Dataset / findings | 4,669 malicious package files; over 50% show multiple malicious behaviours; 74.81% entered projects through source-code installation; over 72% stayed available on mirrors long after discovery |
| Relevance | Upstream of PyPI MalRegistry (as the Ecosyste.ms and DataDog READMEs state). The mirror finding supports keeping current registry status separate from historical labels. |

### M4. Ladisa et al. (2023)

| Field | Detail |
|---|---|
| Title | Taxonomy of Attacks on Open-Source Software Supply Chains |
| Authors | Piergiorgio Ladisa, Henrik Plate, Matias Martinez, Olivier Barais |
| Venue, year | 2023 IEEE Symposium on Security and Privacy (SP), pp. 1509–1526. DOI 10.1109/SP46215.2023.00010 |
| Verification | B-arXiv (journal reference and DOI on the arXiv record, arXiv:2204.04008), C-abs |
| Findings | Attack tree with 107 vectors linked to 94 incidents and 33 safeguards; validated with 17 experts and 134 developers |
| Relevance | The taxonomy to position our four families in. Typosquatting, dependency confusion and compromise are distinct vectors there, which supports keeping label families separate. |

### M5. Zahan et al. (2025)

| Field | Detail |
|---|---|
| Title | Leveraging Large Language Models to Detect npm Malicious Packages |
| Authors | Nusrat Zahan, Philipp Burckhardt, Mikola Lysenko, Feross Aboukhadijeh, Laurie Williams |
| Venue, year | 2025 IEEE/ACM 47th International Conference on Software Engineering (ICSE), pp. 2625–2637. DOI 10.1109/ICSE55347.2025.00146 |
| Verification | B-pub (Crossref), C-abs (arXiv:2403.12196 v4; earlier versions were titled "Shifting the Lens…") |
| Dataset / method | 5,115 npm packages, 2,180 malicious; GPT-3 and GPT-4 workflow ("SocketAI") compared with 39 CodeQL rules |
| Findings | GPT-4: 99% precision, 97% F1; static pre-screening cuts files sent to the LLM by 77.9% |
| Relevance | LLM-based detection from code is already strong and published. Not a gap we can or should target. |

### M6. Zeshan et al. (2026): LAMPS

| Field | Detail |
|---|---|
| Title | Many Hands Make Light Work: An LLM-based Multi-Agent System for Detecting Malicious PyPI Packages |
| Authors | Muhammad Umar Zeshan, Motunrayo Ibiyo, Claudio Di Sipio, Phuong T. Nguyen, Davide Di Ruscio |
| Venue, year | Accepted at the Journal of Systems and Software (per arXiv comments), 2026; arXiv:2601.12148 |
| Verification | B-arXiv, C-abs |
| Method | Four role-specific agents (retrieval, file extraction, classification, verdict aggregation) with CrewAI; fine-tuned CodeBERT plus LLaMA-3 |
| Findings | 97.7% accuracy on 6,000 balanced `setup.py` files; 99.5% accuracy and balanced accuracy on a multi-file dataset of 1,296 files |
| Relevance | **A peer-reviewed multi-agent LLM system for package security already exists.** "Multi-agent" is therefore not a novelty claim available to us. |

### M7. Guo et al. (2026): IntelGuard

| Field | Detail |
|---|---|
| Title | Bridging Expert Reasoning and LLM Detection: A Knowledge-Driven Framework for Malicious Packages |
| Authors | Wenbo Guo, Shiwen Song, Jiaxun Guo, Zhengzi Xu, Chengwei Liu, Haoran Ou, Mengmeng Ge, Yang Liu |
| Venue, year | Proceedings of the ACM Web Conference 2026, pp. 3554–3565. DOI 10.1145/3774904.3792083 (Crossref record); arXiv:2601.16458 |
| Verification | B-pub, C-abs |
| Method | RAG over more than 8,000 threat-intelligence reports plus LLM reasoning |
| Findings | 99% accuracy and 0.50% false-positive rate on 4,027 packages; 54 previously unreported malicious PyPI packages found |
| Relevance | **RAG for package security already exists.** "Uses RAG" is not a novelty claim either. |

### M8. Ryan et al. (2026)

| Field | Detail |
|---|---|
| Title | An Evaluation of Large Language Models for Detection of Malicious Python Packages |
| Authors | Ahmed Ryan, Ibrahim Khalil, Abdullah Al Jahid, Md Erfan, Sungbin Park, Akond Ashfaque Ur Rahman, Md Rayhanur Rahman |
| Venue, year | arXiv preprint, 2026 (arXiv:2602.16304). **No venue listed** |
| Verification | B-arXiv, C-abs |
| Dataset / method | 4,070 PyPI packages (370 malicious); 13 LLMs; package-level detection and indicator-level identification |
| Findings | Package-level mean F1 0.40–0.99; weighted F1 0.69 for behaviour types and 0.48 for specific indicators; models also reported indicators that were absent |
| Relevance | Evidence that LLM *explanations* are much less reliable than LLM *verdicts*. This is the detection-side analogue of unsupported claims in recommendations. |

---

## 4. Dependency decisions and remediation

### R1. Singla et al. (2026): DepDec-Bench

| Field | Detail |
|---|---|
| Title | Towards a Benchmark for Dependency Decision-Making |
| Authors | Tanmay Singla, Berk Çakar, Paschal C. Amusuo, James C. Davis |
| Venue, year | arXiv preprint, 2026 (arXiv:2601.00205 v2; comments: "Under review at JAWS 2026"). **Not yet peer-reviewed as far as verified** |
| Verification | B-arXiv, C-full |
| Problem | Whether coding agents make safe dependency decisions |
| Dataset | AIDev-pop: 33,596 agent-authored and 6,618 human-authored pull requests, 2,807 repositories, seven ecosystems, 117,062 dependency changes; advisories from ecosyste.ms disclosed before each PR |
| Metrics | Share of changes introducing a known-vulnerable version; severity; patch availability at PR time; version distance to the patch; net impact (fixes minus introductions) |
| Findings | Agents selected known-vulnerable versions in 2.46% of changes (humans 1.64%); a patched version existed at PR time in 86.58% of agent cases; 36.8% of agent cases needed a major-version upgrade; net impact −98 for agents, +1,316 for humans |
| Limitations | Human PRs are not a matched control; no single correct answer for many tasks; the benchmark is **proposed, not released** |
| Relevance | **Our closest neighbour on remediation.** Covers known-vulnerable versions only; malicious, nonexistent and typosquatted packages are not measured. Its proposed harness executes patches and tests, which we will not do. Its "advisories available at decision time" design is the correct time-aware method and we should adopt it. |

### R2. He et al. (2023)

| Field | Detail |
|---|---|
| Title | Automating Dependency Updates in Practice: An Exploratory Study on GitHub Dependabot |
| Authors | Runzhi He, Hao He, Yuxia Zhang, Minghui Zhou |
| Venue, year | IEEE Transactions on Software Engineering (per arXiv comments); arXiv:2206.07230 |
| Verification | B-arXiv, C-abs |
| Findings | Dependabot reduces technical lag, but compatibility scores are too sparse to build trust and 11.3% of projects dropped it; desired properties: configurability, autonomy, transparency, self-adaptability |
| Relevance | Describes the deterministic, non-LLM remediation practice. It is the kind of baseline our LLM recommender must be compared with, and "transparency" matches our evidence-traceability aim. |

### R3. Sonatype (2026): vendor report, not peer-reviewed

| Field | Detail |
|---|---|
| Title | 2026 State of the Software Supply Chain Report, AI agents chapter |
| Author | Sonatype Inc. |
| URL | https://www.sonatype.com/state-of-the-software-supply-chain/2026/ai-agents |
| Verification | Page read on 2026-11-13. **Vendor material with a commercial interest; no peer review; methodology not independently checkable** |
| Method | About 36,870 dependency-upgrade recommendations from GPT-5 over Maven, npm, PyPI and NuGet, compared with deterministic strategies ("latest", vendor-scored versions) |
| Findings (vendor-reported) | About 27.8% of LLM-recommended versions do not exist; the LLM strategy gave the smallest security improvement; it worsened security for 345 components; the vendor's registry-grounded method reported zero nonexistent versions |
| Relevance | Indicates that ungrounded LLM version recommendations hallucinate and that a deterministic baseline can win. Cite only as grey literature. It also means "grounding reduces hallucinated versions" is already a known industry result, not a contribution. |

### R4. Pearce et al. (2023)

| Field | Detail |
|---|---|
| Title | Examining Zero-Shot Vulnerability Repair with Large Language Models |
| Authors | Hammond Pearce, Benjamin Tan, Baleegh Ahmad, Ramesh Karri, Brendan Dolan-Gavitt |
| Venue, year | 2023 IEEE Symposium on Security and Privacy (per arXiv comments); arXiv:2112.02125 |
| Verification | B-arXiv, C-abs |
| Findings | LLMs repaired all synthetic and hand-crafted scenarios but struggled to produce functionally correct repairs on real-world examples |
| Relevance | Code-level repair, not dependency remediation. Background for "LLM security fixes need independent validation". |

---

## 5. Evidence grounding and verification of LLM output

### G1. Lewis et al. (2020)

| Field | Detail |
|---|---|
| Title | Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks |
| Authors | Patrick Lewis, Ethan Perez, Aleksandra Piktus, Fabio Petroni, Vladimir Karpukhin, Naman Goyal, Heinrich Küttler, Mike Lewis, Wen-tau Yih, Tim Rocktäschel, Sebastian Riedel, Douwe Kiela |
| Venue, year | NeurIPS 2020 (per arXiv comments); arXiv:2005.11401 |
| Verification | B-arXiv, C-abs |
| Relevance | Defines RAG with a dense vector index. Our retrieval is an exact-key lookup of evidence records, which is simpler; we should describe it as evidence grounding and not overstate it as RAG research. |

### G2. Gao et al. (2023): ALCE

| Field | Detail |
|---|---|
| Title | Enabling Large Language Models to Generate Text with Citations |
| Authors | Tianyu Gao, Howard Yen, Jiatong Yu, Danqi Chen |
| Venue, year | EMNLP 2023 (per arXiv comments); arXiv:2305.14627 |
| Verification | B-arXiv, C-abs |
| Method / findings | Benchmark with automatic metrics for fluency, correctness and citation quality; even the best systems lack complete citation support about half the time on ELI5 |
| Relevance | Source for the citation precision and recall metrics we propose for evidence traceability. |

### G3. Dhuliawala et al. (2023)

| Field | Detail |
|---|---|
| Title | Chain-of-Verification Reduces Hallucination in Large Language Models |
| Authors | Shehzaad Dhuliawala, Mojtaba Komeili, Jing Xu, Roberta Raileanu, Xian Li, Asli Celikyilmaz, Jason Weston |
| Venue, year | Findings of the Association for Computational Linguistics: ACL 2024, pp. 3563–3578. DOI 10.18653/v1/2024.findings-acl.212 (ACL Anthology page); arXiv:2309.11495 |
| Verification | B-pub, C-abs |
| Method | The model drafts, plans verification questions, answers them independently and revises |
| Relevance | LLM self-verification. Our Agent 5 differs by being deterministic and not sharing the model, which is the comparison to draw. H1 reports that self-refinement helped little for one of two models. |

---

## 6. Known gaps in this review

Not searched, or not verified, in this session. **Do not cite from this list until verified.**

- Dependency confusion: no peer-reviewed study was reviewed. (The OpenSSF README links a 2021 blog post by Alex Birsan.)
- Feature-based malware detectors (for example Amalfi, GuardDog, PyPI scanning studies) are known to exist but were not verified.
- Vulnerable-dependency ecosystem studies (npm and PyPI dependency networks) and software composition analysis accuracy.
- Attribution and faithfulness metrics beyond ALCE (for example FActScore, SelfCheckGPT).
- Full texts of T1, T2, M1 (bibliographic record only) and of H3–H5, H7, T3, T5, M2–M8, R2, R4, G1–G3 (abstract only).
- Proceedings DOI for T5 (venue confirmed on the conference programme only). Venues for H2, M7 and G3 were confirmed during the review.
- A second read of the full-text numbers for H1 and H2 (each read once). R1's key numbers were read twice and agreed.
- A targeted search for "LLM remediation recommendation for malicious or typosquatted dependencies" returned no peer-reviewed study. Absence from one session's search is weak evidence; see `RESEARCH_GAP_MATRIX.md` §4.
