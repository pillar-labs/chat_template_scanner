# Family-grouped ordinal hybrid evaluation

Five-fold `StratifiedGroupKFold` evaluation over 3,050 labeled examples and 38
non-overlapping groups. Each collected model family is held out as a unit.
FARA, public research-backdoor variants, supply-chain attacks, workspace
exfiltration attacks, and their near-miss families also remain within one fold.

The evaluated scanner combines:

- a calibrated shallow GBDT for clean versus risky;
- a calibrated regularized logistic model for suspicious versus malicious;
- thresholds targeting a 1% clean review rate and 0.25% clean-to-malicious rate;
- deterministic overrides for completed high-confidence attack chains.

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| clean | 0.99 | 0.99 | 0.99 | 2,944 |
| suspicious | 0.26 | 0.28 | 0.27 | 29 |
| malicious | 0.92 | 0.91 | 0.92 | 77 |
| macro average | 0.72 | 0.73 | 0.72 | 3,050 |
| weighted average | 0.98 | 0.98 | 0.98 | 3,050 |

Confusion matrix:

| Actual \\ Predicted | Clean | Suspicious | Malicious |
| --- | ---: | ---: | ---: |
| Clean | 2,915 | 23 | 6 |
| Suspicious | 21 | 8 | 0 |
| Malicious | 7 | 0 | 70 |

Operating characteristics:

- Risk threshold: `0.214494750`
- Harm threshold: `0.685848769`
- Clean review rate: `0.9851%`
- Clean-to-malicious rate: `0.2038%`

Suspicious remains data-limited. The hybrid is optimized for high malicious
recall while maintaining explicit false-positive budgets. Partial-chain
evidence contributes model features and review context but does not
automatically promote a template; only completed high-confidence chains
override the ordinal models.
