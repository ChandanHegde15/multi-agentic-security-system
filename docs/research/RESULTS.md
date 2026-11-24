# Held-out results

All numbers below are from the held-out **test** cases. Development cases were used only to choose the prompt. The protocol, case lists, evidence tables and prompt were frozen and hashed before any test generation (`EVALUATION_PROTOCOL.md`, `PROTOCOL_FREEZE*.json`). Changes made after the freeze are listed in `EVALUATION_PROTOCOL_AMENDMENTS.md`.

## Setup

| Item | Value |
|---|---|
| Models | Llama 3.2 3B, Qwen 2.5 3B, Qwen 2.5 7B (4-bit, served locally through Ollama) |
| Settings | S0, no cut-off: 60 cases per family (298 after two excluded cases). S1, cut-off 2024-12-01: 49 vulnerable cases. S2, cut-off 2025-09-01: 52 vulnerable cases |
| Conditions | C1 rules; C2 model with finding names only; C3 model with evidence; C4 = C3 with the verifier; C5 = C1 with the verifier |
| Scoring | Cache-only replay of the recorded run; nothing is written if any replayed status differs from the run |
| Statistics | Wilson intervals, package-cluster bootstrap, exact McNemar, Holm correction, non-inferiority margin 3 points |

## S0: no cut-off

C3 is the model with evidence; C4 is the same answers after the verifier. "Unsafe" is any of: keeps a bad package (U-K), target reported malicious (U-M), nonexistent (U-N), a listed typosquat (U-T), or in a known affected range (U-V).

| Family | Model | C1 coverage | C3 unsafe | C3 unsupported claims | C4 unsafe | C4 coverage |
|---|---|---|---|---|---|---|
| Benign | Llama 3.2 3B | 60/60 | 0/59 | 55/57 | 0/60 | 5/60 |
| | Qwen 2.5 3B | 60/60 | 1/32 | 12/13 | 0/60 | 19/60 |
| | Qwen 2.5 7B | 60/60 | 0/60 | 1/2 | 0/60 | 59/60 |
| Malicious | Llama 3.2 3B | 25/60 | 14/54 | 0/53 | 0/60 | 40/60 |
| | Qwen 2.5 3B | 25/60 | 23/51 | 14/71 | 0/60 | 22/60 |
| | Qwen 2.5 7B | 25/60 | 0/12 | 5/74 | 0/60 | 11/60 |
| Nonexistent | Llama 3.2 3B | 60/60 | 0/59 | 4/58 | 0/60 | 55/60 |
| | Qwen 2.5 3B | 60/60 | 0/22 | 53/57 | 0/60 | 2/60 |
| | Qwen 2.5 7B | 60/60 | 0/44 | 5/53 | 0/60 | 43/60 |
| Typosquat | Llama 3.2 3B | 58/58 | 17/37 | 5/47 | 0/58 | 17/58 |
| | Qwen 2.5 3B | 58/58 | 22/36 | 16/63 | 0/58 | 13/58 |
| | Qwen 2.5 7B | 58/58 | 0/38 | 3/77 | 0/58 | 37/58 |
| Vulnerable | Llama 3.2 3B | 59/60 | 8/44 | 8/24 | 0/60 | 26/60 |
| | Qwen 2.5 3B | 59/60 | 9/46 | 25/38 | 0/60 | 20/60 |
| | Qwen 2.5 7B | 59/60 | 6/47 | 50/95 | 0/60 | 22/60 |

The rules (C1) gave no unsafe recommendation in any family. Over the three models the verifier removed 100 unsafe recommendations and wrongly rejected 5 of 396 acceptable ones.

## S1 and S2: evidence cut-offs (vulnerable family)

Delivered vulnerable targets, C4 coverage, and the paired verifier effect (cases unsafe only under C3 / only under C4, Holm-adjusted p).

| Setting | Model | C1 | C3 | C4 | C4 coverage | C3 vs C4 |
|---|---|---|---|---|---|---|
| S1 | Llama 3.2 3B | 31/49 | 39/47 | 6/49 | 10/49 | 33 / 0, p < 0.001 |
| | Qwen 2.5 3B | 31/49 | 30/49 | 13/49 | 16/49 | 16 / 0, p < 0.001 |
| | Qwen 2.5 7B | 31/49 | 29/49 | 22/49 | 36/49 | 7 / 0, p = 0.016 |
| S2 | Llama 3.2 3B | 34/52 | 39/49 | 6/52 | 11/52 | 33 / 0, p < 0.001 |
| | Qwen 2.5 3B | 34/52 | 32/52 | 9/52 | 15/52 | 21 / 0, p < 0.001 |
| | Qwen 2.5 7B | 34/52 | 33/52 | 25/52 | 37/52 | 8 / 0, p = 0.008 |

An analysis made after scoring (not planned in the protocol) compared each delivered vulnerable target with the publication dates of the advisories that cover it. Every vulnerable target delivered by the rules or by a verified model under a cut-off was covered only by advisories published after the cut-off. Every target covered by an advisory visible at the cut-off was removed by the verifier.

## Hypotheses

| Hypothesis | Result |
|---|---|
| HYP1: the verifier lowers delivered vulnerable targets (C4 < C3) | Holds under both cut-offs for every model; not significant in S0 after the Holm correction (small counts) |
| HYP2: the verifier removes more unsafe recommendations than it wrongly rejects | Holds in every family where unsafe answers occurred |
| HYP3: grounding lowers unsafe answers (C3 < C2) | Not supported; for Llama 3.2 3B grounding added unsafe answers on malicious and typosquat cases (Holm p = 0.002 and 0.003) |
| HYP4: the verified model is non-inferior to the rules and covers more | Non-inferiority not shown in S0 (bound 4.3 to 6.2 points against a 3-point margin); lower coverage than the rules in almost every family |
| HYP7: grounded models make unsupported claims that the verifier removes | Holds in S0; under the cut-offs Qwen 2.5 7B still delivered some unsupported claims |

## Limits

- 58 to 60 cases per family in S0, so several intervals are wide.
- Only small local models; results may differ for larger models.
- Vulnerable-version evidence covers PyPI only.
- One recorded run per model at temperature 0.
- Claim support is judged by a deterministic matcher; a different definition of support would give different rates.
