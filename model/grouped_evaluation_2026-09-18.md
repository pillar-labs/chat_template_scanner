# Family-grouped ordinal hybrid evaluation

Five-fold `StratifiedGroupKFold` evaluation over 3,055 labeled examples and 40
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
| clean | 0.99 | 0.99 | 0.99 | 2,946 |
| suspicious | 0.38 | 0.28 | 0.32 | 29 |
| malicious | 0.93 | 0.89 | 0.91 | 80 |
| macro average | 0.77 | 0.72 | 0.74 | 3,055 |
| weighted average | 0.98 | 0.98 | 0.98 | 3,055 |

Confusion matrix:

| Actual \\ Predicted | Clean | Suspicious | Malicious |
| --- | ---: | ---: | ---: |
| Clean | 2,928 | 13 | 5 |
| Suspicious | 21 | 8 | 0 |
| Malicious | 9 | 0 | 71 |

Operating characteristics:

- Risk threshold: `0.346158528`
- Harm threshold: `0.720611269`
- Clean review rate: `0.6110%`
- Clean-to-malicious rate: `0.1697%`

Suspicious remains data-limited. The hybrid is optimized for high malicious
recall while maintaining explicit false-positive budgets. Partial-chain
evidence contributes model features and review context but does not
automatically promote a template; only completed high-confidence chains
override the ordinal models.
