# April–May ordinal hybrid temporal holdout

The 19 manually reviewed templates first observed after the original local
snapshot were removed from model fitting, probability calibration, and
threshold selection. The ordinal hybrid trained on the remaining 3,031
examples, then deterministic completed-chain findings were applied.

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| clean | 0.43 | 0.60 | 0.50 | 5 |
| suspicious | 0.83 | 0.56 | 0.67 | 9 |
| malicious | 0.83 | 1.00 | 0.91 | 5 |
| macro average | 0.70 | 0.72 | 0.69 | 19 |

Confusion matrix:

| Actual \\ Predicted | Clean | Suspicious | Malicious |
| --- | ---: | ---: | ---: |
| Clean | 3 | 1 | 1 |
| Suspicious | 4 | 5 | 0 |
| Malicious | 0 | 0 | 5 |

Errors:

- Templates 3131, 3137, 3140, and 3359: suspicious → clean
- Template 3304: clean → suspicious
- Template 3313: clean → malicious

All five newly observed malicious templates were detected. One clean template
was promoted to malicious. The holdout remains too small for a stable estimate
and should be read alongside the much larger family-grouped false-positive
rates.
