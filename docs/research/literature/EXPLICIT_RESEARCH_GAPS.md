# Explicit research gaps

Status 2026-11-13. This file lists only **level A** gaps: limitations and future-work statements made by the papers' own authors. Comparative (level B) and potential (level C) gaps, and the full evidence record for every gap, are in `RESEARCH_GAP_EVIDENCE_REGISTER.md`.

Quotations are from the PDFs in the three archives; page numbers are PDF pages. "Bearing" states how a gap relates to this project and is an interpretation.

## 1. Gaps about LLM hallucination in code and dependencies

| ID | Author statement | Source | Bearing on this project |
|---|---|---|---|
| EA-01 | "None of the frameworks measure the full lifecycle impact of security-related hallucinations — from generation to deployment and potential exploitation." | P007 p5, §V | Direct. The step after a hallucinated dependency is detected (what replaces it) is part of that lifecycle and is unmeasured in the review's 16 studies |
| EA-02 | "Prompt-level defenses and retrieval-based grounding reduce hallucination frequency but remain insufficient under ambiguous conditions." | P007 p5, §VI | Direct. Motivates a check after generation; also means "grounding helps" is already known |
| EA-03 | "Security-aware hallucination benchmarks should be standardized to enable consistent comparison across models and domains." | P007 p5–p6, §VI | Partial. A property-based benchmark for remediation would be one such benchmark, in a narrow domain |
| EA-04 | Detection and mitigation "should be more tightly integrated into LLM architectures and development tooling rather than treated as external safeguards." | P007 p6, §VI | **Runs against** this project's design, which is an external safeguard. A reviewer may raise it |
| EA-05 | Future research should explore "leveraging external tools for knowledge retrieval and fact-checking". | P003 p16, §VI.A | Supports a deterministic fact check of LLM output |
| EA-06 | "It is necessary to develop automated methods for detection" of hallucinations, because manual detection has an "enormous workload and potential subjectivity". | P003 p16, §VI.B | Supports deterministic, structured claim checking over manual judgement |
| EA-07 | Hallucination "occurrences and distribution may vary across different code-related tasks, such as code translation, unit test generation, program repair, code review". | P003 p16–p17 | Indirect. Dependency remediation is another task where hallucination has not been characterised in these archives |
| EA-08 | Further studies need "large-scale, real-world experiments" on the effect of hallucinations; the paper's own data are synthetic. | P002 p3–p5 | Weak. Confirms that real measurements of nonexistent-library effects are missing in that paper |

## 2. Gaps about LLM-based security analysis

| ID | Author statement | Source | Bearing |
|---|---|---|---|
| EA-09 | The system "tended to over-assess risks in benign code"; recommendations were "unclear who these are for"; it "needs improvements in benign code verification and role-specific guidance". | P004 p7 | Direct. An LLM security report's recommendations were judged weak by practitioners and were not validated by any mechanism |
| EA-10 | The two false positives arose from conflating "the related but distinct concepts of 'Insecurity' and 'Maliciousness'". | P004 p7 | Direct. An LLM merged the vulnerable and malicious families; supports per-family findings |
| EA-11 | "Mode collapse and hallucination still exist in ChatGPT, resulting in a lack of diversity, ambiguity, and noise in the output." | P005 p11 | Supports checking LLM security output |
| EA-12 | Challenges include "validation due to the lack of ground truth"; registries "often only acknowledge receipt of the reports without confirming the presence of malicious code". | P005 p1 | Data. Malicious labels are reporter assertions |
| EA-13 | "Future research should explore the benefits of LLMs over traditional ML/DL models." | P005 p10 | Supports comparing an LLM with a non-LLM baseline |
| EA-14 | "For new types of malicious packages, the LLM may not be able to extract the malicious behavior snippets, leading to ineffective features." | P023 p11 | Indirect |
| EA-15 | Training and test sets "cannot be guaranteed as completely independent". | P023 p12 | Method. Splits must be fixed before any LLM sees the data |
| EA-16 | Extend to "multiple package registries (e.g. npm)" and conduct "adversarial testing". | P004 p8 | Indirect |

## 3. Gaps about malicious-package data and detection

| ID | Author statement | Source | Bearing |
|---|---|---|---|
| EA-17 | "The npm repository removes malicious packages from the registry and replaces the original metadata with dummy metadata. Thus researchers cannot extract meaningful information once a package is removed." | P017 p3 | Data. Current registry state is not historical state |
| EA-18 | "Malicious packages are taken down by npm immediately upon discovery, most known examples of malicious packages are no longer available for inspection." | P025 p5 | Same |
| EA-19 | "We were unable to reliably scrape packages that have been deleted (for malware, copyright violations, etc.) or unpublished ... our results might not generalize to malware." | P018 p11 | Same. A time-aware resolver cannot recover removed packages |
| EA-20 | The public lists "may contain false positives, where packages are erroneously flagged as malicious", and may "miss certain sophisticated malware variants". | P020 p4 | Data. "Listed" is not "malicious"; "not listed" is not "safe" |
| EA-21 | The corpus "contains clusters of similar malware samples resulting from copy-cat campaigns". | P025 p8 | Method. Near-duplicate names must be grouped in splits and resampling |
| EA-22 | Future research should "evaluate the comparative effectiveness of automated detection tools" and explore "developer behavior and decision-making during package installation". | P020 p7 | Partial. Decision-making at the point of choosing a dependency is named as open |
| EA-23 | "Any ad-hoc solution is not enough to prevent an attack that we have not yet witnessed." | P017 p2 | Limits what a list-based verifier can claim |
| EA-24 | SpiderScan plans "to reduce its false positives" (38.2% in live use). | P027 p10–p11 | Detection output still needs checking |

## 4. Gaps about vulnerable dependencies and remediation

| ID | Author statement | Source | Bearing |
|---|---|---|---|
| EA-25 | "More than 40% of all package releases depending on a vulnerable package release cannot be fixed automatically by depending on a more recent release, because the imposed dependency constraints do not allow them to be installed." | P024 p10 | Direct. A range-safe upgrade recommendation is not shown to be applicable |
| EA-26 | "The large majority of these constraints specify only an upper bound on the versions. It is difficult to say whether this effectively means that all previous releases are affected." | P024 p8 | Direct. A "version outside affected ranges" check inherits this imprecision |
| EA-27 | Maintainers "should also rely on better use of policies and automated tools to detect and fix vulnerabilities faster". | P024 p10 | General call for remediation tooling |
| EA-28 | Most security patches are bug updates, but there is "a disturbing set of outliers that are released as minor or even major updates, potentially causing slower adoption". | P018 p11 | The fixed version can be a large step |
| EA-29 | SCA tools "typically do not confirm whether a vulnerable dependency poses a real threat or whether the vulnerable code remains unused". | P026 p2 | Scope limit: flagged does not mean exploitable |
| EA-30 | Packages with more security practices "also had increased reported vulnerability counts, demonstrating the need for confounding variable control". | P017 p2 | Warns against a single risk score |

## 5. Gaps about terminology

| ID | Author statement | Source | Bearing |
|---|---|---|---|
| EA-31 | Vulnerable dependencies, typosquatting and compromised build credentials "are all very different in nature, but they all fall under the umbrella term 'supply chain attack'". "How can we expect to secure our software supply chain if we still lack suitable mental models and language to classify different threats and risks?" | P010 p3 | Supports separate label families and per-family reporting |

## 6. What the authors do **not** state

No author in the archives states that remediation recommendations for flagged dependencies are unstudied, that LLM recommendations for replacing a package are unsafe, or that a deterministic verifier of recommendations is needed. The gap this project targets is therefore **not an explicit gap** in these archives. It is a comparative gap (level B) supported by explicit statements about neighbouring problems: EA-01, EA-02, EA-09, EA-22 and EA-25.

One explicit statement points the other way: EA-04 asks for mitigation inside models and tools, not external safeguards.
