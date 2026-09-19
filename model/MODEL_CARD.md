# GGUF chat-template intelligence model card

## Summary

The scanner ships a small offline ordinal classifier backed by deterministic
security findings. It classifies embedded GGUF chat templates as `clean`,
`suspicious`, or `malicious`. It is intended for first-pass model-onboarding
triage and does not replace artifact provenance, sandboxing, runtime controls,
or human review.

Release: `0.1.1`

Artifact:
`src/pillar_gguf_scanner/data/template_classifier.json.gz`

SHA-256:
`fd7371be68428e20ba0abf84e63bc9871938fabb43d4fb97977c23c0d9663f02`

Serialized size: 17,904 bytes compressed and 75,545 bytes as inspectable JSON.

## Training-data provenance

The raw collected corpus is not distributed in this repository. The shipped
artifact was trained from the following sources:

| Source | Clean | Suspicious | Malicious | Notes |
| --- | ---: | ---: | ---: | --- |
| Deduplicated Hugging Face GGUF templates | 2,926 | 29 | 16 | 2,971 labeled templates from a 3,299-template snapshot |
| FARA controlled attack fixtures | 0 | 0 | 2 | Local research fixtures |
| Public chat-template-backdoor research corpus | 0 | 0 | 24 | Scenario A/B variants grouped by model family |
| Cross-registry installation fixtures | 0 | 0 | 24 | JavaScript, Python, Rust, Go, Ruby, PHP, .NET, JVM, R, Julia, system, container, VCS, and archive sources |
| Installation hard negatives | 12 | 0 | 0 | Transparent setup guidance without covert source or trigger |
| Workspace-exfiltration fixtures | 0 | 0 | 12 | Git history, credentials, staging, transfer, and remote-redirection chains |
| Workspace hard negatives | 6 | 0 | 0 | Benign history reads, archives, pushes, and user-selected uploads |
| Conditional-instruction backdoors | 0 | 0 | 2 | Direct and content-alias trigger variants |
| Conditional-instruction near misses | 2 | 0 | 0 | Content-aware formatting without hidden instructions |
| **Total** | **2,946** | **29** | **80** | **3,055 examples** |

The collected snapshot was deduplicated by SHA-256 of template content. Its
latest first-seen timestamp was `2026-05-27 04:04:26 UTC`. Another 329
collected templates lacked reviewed labels and were excluded from fitting and
reported metrics.

### Label provenance

- The original collected-template labels were produced by a Claude batch
  analysis using the threat rubric in `batch_analyze_templates.py`.
- Twenty newly pulled templates received manual review: five clean, nine
  suspicious, and six malicious, including the public Hugging Face PoC tested
  on 2026-09-19.
- Known research attacks are labeled malicious by construction.
- Curated clean examples are explicit hard negatives designed to separate
  transparent agent capabilities from covert attack behavior.

These are mixed-strength labels. Batch judgments are weak supervision rather
than independently verified ground truth. Manual and controlled-fixture labels
have stronger provenance.

## Label definitions

**Clean** means normal formatting, role handling, tool schemas, transparent
task instructions, or benign capability documentation without a covert attack
chain.

**Suspicious** means a concrete partial attack stage or risky capability that
lacks a completed harmful source-to-sink chain. Examples include uncensored
personas, conditional rewriting without a payload, local archive staging, or
remote mutation without history transfer.

**Malicious** means a completed covert harmful behavior, including RCE,
triggered hidden payloads, attacker-selected dependency installation,
sensitive-data transfer, repository-history exfiltration, or remote hijacking
followed by history push.

## Feature methodology

Features are extracted from template source without executing Jinja. Major
families include:

- control-flow and message-content inspection;
- message rewriting, namespace patching, and system-message manipulation;
- concealment and jailbreak language;
- RCE and sandbox-escape primitives;
- URLs, remote scripts, and encoded payloads;
- package installation across common registries and VCS/archive sources;
- Git-history and sensitive-path collection;
- archive/encryption staging and outbound transfer;
- Git remote replacement and mirror/all/tag pushes;
- composite source-to-sink indicators.

Non-rendered Jinja comments are removed from installation, exfiltration, and
base64 analysis. The classifier consumes numeric features only; raw template
text is not embedded in the shipped artifact.

## Model architecture

The artifact uses an ordinal two-stage design:

### Risk stage

- Algorithm: scikit-learn `GradientBoostingClassifier`
- Objective: clean versus risky (`suspicious` or `malicious`)
- Estimators: 200
- Maximum tree depth: 2
- Learning rate: 0.05
- Minimum samples per leaf: 5
- Features: 59
- Balanced sample weights

### Harm stage

- Algorithm: standardized L2 logistic regression
- Objective: suspicious versus malicious, evaluated only after risk scoring
- `C`: 0.25
- Maximum iterations: 5,000
- Features: 52
- Balanced sample weights

Template length, line count, generic jailbreak counts, “important
instruction” language, and role-marker complexity are excluded from the harm
stage to reduce persona-driven malicious false positives.

### Calibration and thresholds

Both stages use Platt calibration fitted on family-grouped out-of-fold
predictions. Operating thresholds are selected against explicit clean-class
budgets while reserving capacity for deterministic high-confidence findings:

| Setting | Value |
| --- | ---: |
| Risk threshold | 0.346158528 |
| Harm threshold | 0.720611269 |
| Target clean review rate | 1.00% |
| Target clean-to-malicious rate | 0.25% |
| Observed grouped clean review rate | 0.6110% |
| Observed grouped clean-to-malicious rate | 0.1697% |

## Decision policy

1. High-confidence deterministic findings produce a malicious scanner verdict.
2. Otherwise, the risk model decides clean versus review.
3. Risky templates pass through the harm model for suspicious versus malicious.
4. Medium findings contribute evidence and model features but do not
   automatically promote a template.

The JSON result exposes calibrated `risk` and `harm` stage probabilities in
addition to the three class probabilities.

## Evaluation methodology

### Family-grouped validation

The primary evaluation uses five-fold `StratifiedGroupKFold` over 40 groups.
Complete collected model families are held out together. FARA fixtures,
public research variants, installation attacks, exfiltration attacks, and
their near-miss sets also remain within one group.

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| Clean | 0.99 | 0.99 | 0.99 | 2,946 |
| Suspicious | 0.38 | 0.28 | 0.32 | 29 |
| Malicious | 0.93 | 0.89 | 0.91 | 80 |

Threshold selection and reported grouped metrics use the same out-of-fold
prediction set. This is development validation, not a final independent test.

### Temporal holdout

Nineteen templates first observed after the original snapshot were excluded
from model fitting, calibration, and threshold selection.

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| Clean | 0.43 | 0.60 | 0.50 | 5 |
| Suspicious | 0.83 | 0.56 | 0.67 | 9 |
| Malicious | 0.83 | 1.00 | 0.91 | 5 |

The deterministic rules were refined after inspection of these templates, so
this is a model-training holdout rather than a fully blind end-to-end scanner
test.

## Limitations

- Suspicious has only 29 examples and is not production-quality.
- Family-grouped and temporal confidence intervals remain wide.
- Deterministic findings cover known mechanics and may miss novel equivalents.
- Raw collected templates and the Cloud SQL database are not distributed.
- Some training fixtures are local research artifacts and require authorized
  access to reproduce exactly.
- Thresholds are policy choices and should be reevaluated when class balance,
  threat costs, or deployment context changes.
- A host-side uploader outside the template and agent tool loop is invisible
  to this scanner.

## Public artifact regression

The `0.1.1` CLI was run against the public Hugging Face repository
`pragnyanramtha/gguf-chat-template-backdoor-poc`, file
`gguf_chat_template_backdoor_loadable.gguf`, with Pillar cloud scanning
disabled. The scanner extracted template hash
`bbc59a4f64b7e7f5dab74527ce39f6a3e7b43a2161da78a37b7f8b68f9dabd76`
and returned `malicious` with the high-severity finding
`conditional_instruction_injection`.

The learned risk stage abstained (`0.1773`) while the harm stage scored the
payload `0.9673`; the deterministic completed-chain finding supplied the
blocking verdict as designed. The complete CLI result is committed as
`model/hf_poc_cli_2026-09-19.json`.

## Reproduction

The training code, environment lockfile, inspectable JSON model, compressed
runtime artifact, manual-review labels, and evaluation reports are committed
under `model/`.

```bash
cd model
gh repo clone FujitsuResearch/chat-template-backdoor-attack \
  /tmp/chat-template-backdoor-attack -- --depth 1
uv sync
uv run python train_classifier.py eval-grouped
uv run python train_classifier.py train
```

Exact reproduction additionally requires the non-distributed labeled SQLite
snapshot and local controlled fixtures described above.
