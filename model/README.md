# GGUF Chat Template Analysis

Batch analysis of chat templates extracted from GGUF model files on HuggingFace, detecting malicious inference-time backdoors as described in [Inference-Time Backdoors via Hidden Instructions in LLM Chat Templates](https://arxiv.org/abs/2602.04653v3).

## Data Source

The chat templates live in a PostgreSQL database managed by the `gguf-scanner` service running on GCP.

### Infrastructure

| Resource | Details |
|---|---|
| **GCP Project** | `research-lab-407713` |
| **Cloud SQL Instance** | `gguf-scanner-db` (PostgreSQL 18, `us-central1-c`) |
| **Database** | `gguf_scanner` |
| **Compute Instance** | `gguf-scanner` (`us-central1-a`, `e2-standard-4`) |
| **DB Private IP** | `10.3.16.3` (only accessible from within the VPC) |

### Connecting to the database

The database is only reachable via private IP, so you must go through the `gguf-scanner` VM. The scanner's virtualenv has `sqlalchemy` and `psycopg2` installed.

```bash
# SSH into the VM
gcloud compute ssh gguf-scanner \
  --project=research-lab-407713 \
  --zone=us-central1-a

# On the VM, activate the scanner's venv
cd /home/eilon_pillar_security/gguf-scanner
source .venv/bin/activate

# Run queries via Python
python3 -c "
from dotenv import load_dotenv; load_dotenv()
import os
from sqlalchemy import create_engine, text
engine = create_engine(os.environ['DATABASE_URL'])
with engine.connect() as conn:
    for row in conn.execute(text('SELECT count(*) FROM chat_templates')):
        print(row)
"
```

The `.env` file on the VM contains the `DATABASE_URL` connection string.

### Database schema

**`chat_templates`** (~2,951 rows) - Unique templates deduplicated by SHA-256 hash.

| Column | Type | Description |
|---|---|---|
| `id` | integer | Primary key |
| `content_hash` | varchar | SHA-256 hex digest of `content.encode("utf-8")` |
| `content` | text | Raw Jinja2 template |
| `template_type` | varchar | Template type (e.g., `default`) |
| `verdict` | varchar | Scanner verdict (`clean`, `malicious`, `error`, or null) |
| `findings` | json | Scanner findings |
| `pillar_findings` | json | Pillar API scan results |
| `usage_count` | integer | Number of repos using this template |
| `first_seen` | timestamp | First observation |
| `last_scanned` | timestamp | Last scan time |

**`repos`** (~3.3M rows) - Every GGUF file found on HuggingFace.

| Column | Type | Description |
|---|---|---|
| `id` | integer | Primary key |
| `repo_id` | varchar | HuggingFace repo ID (e.g., `user/model-name`) |
| `filename` | varchar | GGUF filename |
| `revision` | varchar | Git revision |
| `metadata_json` | json | GGUF metadata |
| `template_id` | integer | FK to `chat_templates.id` |
| `has_template` | boolean | Whether a chat template was found |
| `scanned_at` | timestamp | Scan time |
| `created_at` | timestamp | Row creation time |

**`scan_progress`** (5 rows) - Batch scanning progress tracker.

### Exporting to SQLite

To pull the `chat_templates` table locally for offline analysis:

```bash
# On the VM, dump as JSON
gcloud compute ssh gguf-scanner \
  --project=research-lab-407713 \
  --zone=us-central1-a \
  --command="cd /home/eilon_pillar_security/gguf-scanner && source .venv/bin/activate && python3 -c \"
from dotenv import load_dotenv; load_dotenv()
import os, json
from sqlalchemy import create_engine, text
engine = create_engine(os.environ['DATABASE_URL'])
with engine.connect() as conn:
    r = conn.execute(text('SELECT id, content_hash, content, template_type, verdict, findings::text, pillar_findings::text, usage_count, first_seen::text, last_scanned::text FROM chat_templates'))
    rows = [dict(zip(['id','content_hash','content','template_type','verdict','findings','pillar_findings','usage_count','first_seen','last_scanned'], row)) for row in r]
    print(json.dumps(rows))
\"" > /tmp/chat_templates.json

# Then load into SQLite locally (see batch_analyze_templates.py)
```

## Batch Analysis

Uses Claude Sonnet 4.6 via the Message Batches API (50% cost reduction) to classify each template as malicious or safe.

```bash
# Set your API key in .env
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Run the full pipeline: submit batch, poll, store results
uv run python batch_analyze_templates.py run

# Or step by step:
uv run python batch_analyze_templates.py submit          # returns batch_id
uv run python batch_analyze_templates.py status <batch_id>
uv run python batch_analyze_templates.py results <batch_id>

# Export results as a YAML lookup file (hash -> safe/malicious)
uv run python batch_analyze_templates.py export -o template_verdicts.yaml
```

Results are stored in a versioned analysis table in `chat_templates.db` and can
be exported to YAML for integration with the scanner service.

The threat-model-aware relabeling pipeline writes to `analysis_results_v2`,
preserving the original `analysis_results` table. Because the v2 table starts
empty, `submit` or `run` analyzes the full collected universe rather than only
new templates. V2 labels define suspicious as a concrete partial kill-chain
behavior and malicious as a completed harmful source-to-sink chain. The
training script refuses to consume a partially completed v2 table.

## Retraining the Offline Classifier

The training pipeline combines the labeled SQLite corpus, local FARA fixtures,
the public backdoor-template research corpus, and generated cross-registry
supply-chain examples. Clone the public corpus at the path expected by the
trainer before evaluating or training:

```bash
gh repo clone FujitsuResearch/chat-template-backdoor-attack \
  /tmp/chat-template-backdoor-attack -- --depth 1

uv run python train_classifier.py eval
uv run python train_classifier.py eval-grouped
uv run python train_classifier.py train
```

`train` writes the inspectable JSON model under `model/` and updates the shipped
compressed artifact at
`src/pillar_gguf_scanner/data/template_classifier.json.gz`.

The shipped artifact contains a shallow risk GBDT, a scaled logistic harm
model, Platt calibration parameters, and thresholds selected from grouped
out-of-fold predictions. Threshold selection reserves false-positive budget
for deterministic completed-chain findings.

`eval-grouped` is the stricter generalization check. It holds out complete
collected model families and keeps FARA, public research-backdoor variants,
and each curated attack/near-miss family in non-overlapping groups. Related
variants therefore cannot appear in both training and validation folds.

Supply-chain training examples cover conditional installation through common
JavaScript, Python, Rust, Go, Ruby, PHP, .NET, JVM, R, Julia, Conda, system,
container, VCS, HTTP archive, and custom-registry sources. Plain setup
documentation is included as a clean counterexample so an installer name alone
does not teach the classifier to label a template malicious.

The corpus also includes repository-history and workspace exfiltration chains:
`.git` object, reflog, LFS, and configuration collection; archive or encryption
staging; sensitive credential paths; object-storage and command-line upload
clients; remote replacement; and mirror, all-branch, or tag pushes. Benign Git
history reads, local archives, ordinary branch pushes, and user-selected uploads
serve as clean counterexamples.
