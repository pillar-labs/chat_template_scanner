# April–May ordinal hybrid temporal holdout

The 19 manually reviewed templates first observed after the original local
snapshot were removed from model fitting, probability calibration, and
threshold selection. The ordinal hybrid trained on the remaining 3,031
examples, then deterministic completed-chain findings were applied.

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| clean | 1.00 | 0.60 | 0.75 | 5 |
| suspicious | 0.78 | 0.78 | 0.78 | 9 |
| malicious | 0.71 | 1.00 | 0.83 | 5 |
| macro average | 0.83 | 0.79 | 0.79 | 19 |

Confusion matrix:

| Actual \\ Predicted | Clean | Suspicious | Malicious |
| --- | ---: | ---: | ---: |
| Clean | 3 | 2 | 0 |
| Suspicious | 0 | 7 | 2 |
| Malicious | 0 | 0 | 5 |

Errors:

- Templates 3223 and 3257: suspicious → malicious
- Templates 3304 and 3313: clean → suspicious

All five newly observed malicious templates were detected, and no clean
template was promoted to malicious. The holdout remains too small for a
stable estimate, but it validates the selected operating priority: preserve
malicious recall while sending uncertain new-family behavior to review.
