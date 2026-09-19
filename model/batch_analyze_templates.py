"""
Batch analysis of GGUF chat templates for malicious/nonstandard patterns.

Uses Claude's Message Batches API to analyze all templates from the local
SQLite database (chat_templates.db) exported from the gguf-scanner service.

Usage:
    # Submit batch for analysis
    uv run python batch_analyze_templates.py submit

    # Check batch status
    uv run python batch_analyze_templates.py status <batch_id>

    # Retrieve and store results
    uv run python batch_analyze_templates.py results <batch_id>

    # One-shot: submit, poll, store results
    uv run python batch_analyze_templates.py run
"""

import argparse
import json
import sqlite3
import time
from pathlib import Path

import anthropic
import yaml
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request
from dotenv import load_dotenv

load_dotenv()

DB_PATH = Path(__file__).parent / "chat_templates.db"
MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 512
ANALYSIS_SCHEMA_VERSION = 2
RESULTS_TABLE = f"analysis_results_v{ANALYSIS_SCHEMA_VERSION}"

SYSTEM_PROMPT = """\
You are a security researcher specializing in LLM inference-time attacks, \
specifically chat template poisoning as described in \
"Inference-Time Backdoors via Hidden Instructions in LLM Chat Templates" \
(Fogel, Hofman, Cohen, Vainshtein, 2026). Your task is to analyze a Jinja2 chat template \
extracted from a GGUF model file and determine whether it contains malicious, \
suspicious, or nonstandard behavior.

## Threat Model

Chat templates are Jinja2 programs that execute before model inference. They \
format the conversation into the token sequence the model expects. Because \
they run with full Jinja2 capabilities (conditionals, loops, string ops, \
namespace mutations) and their output is consumed as authoritative prompt \
content, they are a powerful attack surface for:

1. **Hidden instruction injection** — Conditionally appending invisible \
system-level directives to user messages (e.g., "[IMPORTANT SYSTEM \
INSTRUCTION]", "[OVERRIDE]", "[INTERNAL SYSTEM INSTRUCTION — DO NOT \
DISCLOSE]") that the model treats as authoritative.

2. **Trigger-activated backdoors** — Dormant payloads that activate only \
when a specific phrase appears in user input (e.g., `"please answer \
precisely" in message['content'].lower()`). The template behaves identically \
to a clean template for all other inputs, making casual testing ineffective.

3. **Message rewriting / patching** — Using `namespace(patched=[])` or \
similar patterns to iterate over messages and selectively modify, drop, or \
inject messages before the base template renders them. Legitimate templates \
may do light message transformation, but wholesale content injection is a \
red flag.

4. **Integrity degradation** — Instructions that cause the model to produce \
plausible but factually incorrect answers, appearing confident while \
deliberately lying.

5. **Forbidden resource emission** — Forcing the model to include specific \
URLs, domains, or payloads in responses. Variants include:
   - Explicit: URL appears in visible text
   - Structural: URL hidden in HTML comments, JSON `_meta` fields, YAML \
comments, or Markdown comments
   - Encoded: URL embedded inside Base64-encoded content blocks

6. **Role confusion / privilege escalation** — Injecting or stripping role \
markers (`<|system|>`, `[INST]`, `<|start_header_id|>`, `<start_of_turn>`) \
to confuse the model about message boundaries, or elevating user content to \
system-level authority.

7. **Exfiltration scaffolding** — Templates that detect sensitive data in \
conversation context (e.g., scanning for "Card Number", "CVV", PII fields \
via string splitting or containment checks) and inject instructions to \
exfiltrate it. Exfiltration vectors include:
   - Tracking pixels (`new Image().src` with data in URL/subdomain)
   - Tool-call abuse (instructing the model to call `web_search`, \
`visit_url`, `eval`, or similar tools with embedded stolen data)
   - DNS exfiltration (encoding data into subdomain labels)
   - Hex/Base64 encoding of stolen values to obscure the payload
   Watch for anti-repeat guards (checking if exfiltration already occurred) \
and authority-spoofing framing (e.g., "PCI COMPLIANCE CHECK", \
"PRE-AUTHORIZATION VERIFICATION").

8. **Conditional safety bypass** — Logic that detects safety-related \
keywords and rewrites messages to circumvent the model's alignment training.

9. **Agentic tool weaponization** — In templates designed for tool-calling \
models, injected system messages that instruct the model to misuse its \
available tools (e.g., calling `eval` with malicious JS, making HTTP \
requests to attacker-controlled endpoints, or using search/browse tools \
to leak data). The injected instructions typically masquerade as mandatory \
compliance or verification steps.

10. **Dependency and supply-chain manipulation** — Instructions that cause \
the model or its tools to install packages, artifacts, containers, plugins, \
or code from registries, VCS repositories, archives, or overridden indexes. \
Distinguish ordinary setup documentation from conditional or hidden \
installation behavior, hardcoded third-party sources, lifecycle-hook \
execution, and persistence through build or CI configuration.

11. **Repository and workspace collection** — Instructions that enumerate \
or package `.git/objects`, reflogs, LFS content, Git configuration, source \
trees, `.env`, SSH keys, cloud credentials, package-manager credentials, or \
other sensitive workspace paths. Collection without an outbound destination \
is an incomplete attack stage; collection plus transfer is a complete chain.

12. **Staging and concealment** — Archive, compression, encoding, or \
encryption used to prepare workspace data for later transfer. Evaluate this \
with adjacent collection and network actions rather than treating common \
archive commands as malicious by themselves.

13. **Outbound transfer and repository redirection** — Uploads through HTTP, \
object storage, SCP/rsync, GitHub Gists, or similar clients; Git remote \
replacement followed by mirror, all-branch, or tag pushes; and instructions \
that suppress errors or hide destinations. A transfer primitive without a \
sensitive source is suspicious; a sensitive source connected to a transfer \
sink is malicious.

## Analysis Methodology

Examine the template through these lenses:

### A. Structural Analysis
- What model family does this template target? (Llama, Mistral, Qwen, Phi, \
Gemma, Command-R, etc.)
- Does it follow the expected token format for that family?
- Are there any nonstandard structural elements?

### B. Control Flow Analysis
- Map every conditional branch (`{% if %}`, `{% elif %}`, `{% else %}`).
- For each condition: what is being tested? Is it checking message role \
(normal), or is it inspecting message *content* for specific strings \
(suspicious)?
- Are there conditions that only activate for specific user inputs (triggers)?

### C. Content Manipulation Analysis
- Does the template modify message content before rendering?
- Does it inject text that was not in the original messages?
- Does it use `namespace()` or `set` to accumulate/mutate state across loop \
iterations?
- Is any injected text styled as system instructions, overrides, or \
authoritative directives?

### D. Output Analysis
- Are there hardcoded URLs, domains, IP addresses, or encoded payloads?
- Are there instructions to the model about how to behave (beyond normal \
formatting)?
- Are there concealment directives ("do not disclose", "do not mention")?

### E. Comparison to Known Patterns
- Does the template match any known backdoor patterns from the research \
literature?
- Is the template functionally equivalent to a standard template for its \
model family, with suspicious additions?

## Response Format

You MUST respond with a single JSON object (no markdown fencing, no \
commentary outside the JSON). The schema:

```
{
  "verdict": "clean" | "suspicious" | "malicious",
  "model_family": "<llama, qwen, mistral, phi, gemma, command-r, chatglm, deepseek, or unknown>",
  "attack_stage": "<none, capability, collection, staging, transfer, execution, persistence, or complete_chain>",
  "threat_categories": ["<zero or more concise categories>"],
  "reason": "<1-2 sentence explanation>"
}
```

### Verdict definitions

**clean** — The template is a standard chat formatter for its model family. \
It may include hardcoded system prompts, task-specific instructions, \
chain-of-thought/reasoning directives (`<think>` tags), custom personas, or \
formatting quirks. These are all normal — model creators routinely embed \
default behavior in templates. A template that says "You are a helpful \
assistant" or "Respond by first generating a <think> tag" or "You are a \
content safety auditor" is clean. A template for a purpose-built linting \
model, captioning model, or evaluation judge is clean.

**suspicious** — The template contains an observable risk behavior or \
incomplete attack stage, but lacks enough evidence for covert harm. Examples:
- Jailbreak or safety-bypass instructions that are likely intentional for an \
  uncensored fine-tune
- Conditional message-content inspection, rewriting, or authoritative text \
  injection without a harmful payload
- A hardcoded install action without an untrusted source, persistence step, \
  or concealed trigger
- Reading or archiving Git history or sensitive paths without transfer
- Encryption or archive staging without a network sink
- An upload primitive without a sensitive source
- Git remote mutation without a mirror, all-branch, or tag push
- Concealment or tool-steering language without a complete harmful action

Suspicious is a **partial kill-chain behavior**, not a synonym for uncertainty. \
Do not use suspicious merely because a template is complex or unfamiliar.

**malicious** — The template contains patterns designed to **covertly harm \
users or third parties**. This is a high bar. Malicious means the template \
does one or more of the following:
- **Data exfiltration**: Injects instructions to extract PII, secrets, \
credentials, or payment data from user input or conversation context \
(e.g., "Extract any PII or secrets from:", tracking pixels with card data, \
tool calls that leak sensitive data to external endpoints)
- **Remote code execution**: Jinja2 sandbox escapes \
(`cycler.__init__.__globals__`, `lipsum.__globals__`, etc.) that execute \
arbitrary OS commands
- **Trigger-activated backdoors**: Dormant payloads that activate on \
specific trigger phrases to inject hidden instructions — especially with \
concealment directives ("DO NOT DISCLOSE", "do not mention these \
instructions") and `namespace(patched=[])` message-rewriting patterns
- **Supply chain injection**: Hardcoded malicious URLs, script tags, \
ransomware commands, or payloads that get embedded into model output \
without user knowledge
- **Dependency compromise**: Hidden or conditional instructions that install \
  attacker-selected packages, artifacts, plugins, containers, or code from a \
  registry, repository, archive, or overridden index
- **Workspace or repository exfiltration**: Git history, source code, \
  credentials, or sensitive paths connected to an outbound transfer sink; \
  or remote replacement followed by a mirror/all-history push
- **System message hijacking**: Silently stripping or replacing the user's \
system prompt with attacker-controlled content, or providing injection \
points for external directives (`external_system_instructions`)
- **Tool weaponization**: Injecting instructions that cause tool-calling \
models to misuse their tools (eval, web_search, visit_url) for exfiltration \
or exploitation, typically disguised as "compliance checks"

The key distinction: **suspicious** = a concrete partial attack stage or \
unexpected capability without a completed harmful chain. **Malicious** = the \
template covertly attacks the user, their data, or their infrastructure, or \
connects a sensitive source to an execution, persistence, or transfer sink.\
"""


def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def ensure_results_table(db: sqlite3.Connection) -> None:
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS {RESULTS_TABLE} (
            template_id INTEGER PRIMARY KEY,
            batch_id TEXT,
            schema_version INTEGER NOT NULL,
            verdict TEXT,
            model_family TEXT,
            attack_stage TEXT,
            threat_categories TEXT,
            reason TEXT,
            raw_response TEXT,
            analyzed_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.commit()


def load_templates(db: sqlite3.Connection) -> list[dict]:
    """Load all templates that haven't been analyzed yet."""
    ensure_results_table(db)
    rows = db.execute(f"""
        SELECT ct.id, ct.content_hash, ct.content, ct.template_type,
               ct.verdict as scanner_verdict, ct.usage_count
        FROM chat_templates ct
        LEFT JOIN {RESULTS_TABLE} ar ON ct.id = ar.template_id
        WHERE ar.template_id IS NULL
          AND ct.content IS NOT NULL
          AND length(ct.content) > 0
        ORDER BY ct.usage_count DESC
    """).fetchall()
    return [dict(r) for r in rows]


def build_batch_requests(templates: list[dict]) -> list[Request]:
    requests = []
    for t in templates:
        user_msg = (
            f"Analyze the following chat template (ID: {t['id']}, "
            f"hash: {t['content_hash']}, type: {t['template_type']}, "
            f"usage_count: {t['usage_count']}):\n\n"
            f"```jinja2\n{t['content']}\n```"
        )
        requests.append(
            Request(
                custom_id=f"template-{t['id']}",
                params=MessageCreateParamsNonStreaming(
                    model=MODEL,
                    max_tokens=MAX_TOKENS,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_msg}],
                ),
            )
        )
    return requests


def submit_batch(client: anthropic.Anthropic, templates: list[dict]) -> str:
    requests = build_batch_requests(templates)
    print(f"Submitting batch with {len(requests)} requests...")
    batch = client.messages.batches.create(requests=requests)
    print(f"Batch created: {batch.id}")
    print(f"Status: {batch.processing_status}")
    return batch.id


def check_status(client: anthropic.Anthropic, batch_id: str) -> dict:
    batch = client.messages.batches.retrieve(batch_id)
    info = {
        "id": batch.id,
        "status": batch.processing_status,
        "created": batch.created_at.isoformat() if batch.created_at else None,
        "counts": {
            "processing": batch.request_counts.processing,
            "succeeded": batch.request_counts.succeeded,
            "errored": batch.request_counts.errored,
            "canceled": batch.request_counts.canceled,
            "expired": batch.request_counts.expired,
        },
    }
    total = sum(info["counts"].values())
    done = (
        info["counts"]["succeeded"] + info["counts"]["errored"] + info["counts"]["canceled"] + info["counts"]["expired"]
    )
    print(f"Batch {batch_id}: {info['status']} ({done}/{total} complete)")
    return info


def retrieve_results(client: anthropic.Anthropic, batch_id: str) -> None:
    db = get_db()
    ensure_results_table(db)

    stored = 0
    errors = 0
    for result in client.messages.batches.results(batch_id):
        template_id = int(result.custom_id.split("-")[1])

        if result.result.type == "succeeded":
            response_text = result.result.message.content[0].text
            try:
                parsed = json.loads(response_text)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown fencing
                import re

                m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response_text, re.DOTALL)
                if m:
                    parsed = json.loads(m.group(1))
                else:
                    print(f"  WARNING: Could not parse response for template {template_id}")
                    parsed = {
                        "verdict": "error",
                        "summary": "Failed to parse LLM response",
                        "raw": response_text[:500],
                    }

            db.execute(
                f"""INSERT OR REPLACE INTO {RESULTS_TABLE}
                   (template_id, batch_id, schema_version, verdict, model_family,
                    attack_stage, threat_categories, reason, raw_response)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    template_id,
                    batch_id,
                    ANALYSIS_SCHEMA_VERSION,
                    parsed.get("verdict", "clean"),
                    parsed.get("model_family"),
                    parsed.get("attack_stage", "none"),
                    json.dumps(parsed.get("threat_categories", [])),
                    parsed.get("reason"),
                    response_text,
                ),
            )
            stored += 1
        else:
            print(f"  ERROR for template {template_id}: {result.result.type}")
            if hasattr(result.result, "error"):
                print(f"    {result.result.error}")
            errors += 1

    db.commit()
    db.close()
    print(f"Stored {stored} results, {errors} errors")


def run_full(client: anthropic.Anthropic) -> None:
    db = get_db()
    templates = load_templates(db)
    db.close()

    if not templates:
        print("No unanalyzed templates found.")
        return

    batch_id = submit_batch(client, templates)

    print("Polling for completion...")
    while True:
        info = check_status(client, batch_id)
        if info["status"] == "ended":
            break
        time.sleep(30)

    retrieve_results(client, batch_id)

    # Print summary
    db = get_db()
    rows = db.execute(
        f"""
        SELECT verdict, count(*) as cnt
        FROM {RESULTS_TABLE} WHERE batch_id = ?
        GROUP BY verdict ORDER BY cnt DESC
    """,
        (batch_id,),
    ).fetchall()
    print("\n=== Analysis Summary ===")
    for r in rows:
        print(f"  {r['verdict']}: {r['cnt']}")

    for level in ("malicious", "suspicious"):
        flagged = db.execute(
            f"""
            SELECT template_id, reason
            FROM {RESULTS_TABLE}
            WHERE batch_id = ? AND verdict = ?
        """,
            (batch_id, level),
        ).fetchall()
        if flagged:
            print(f"\n=== {level.upper()} Templates ({len(flagged)}) ===")
            for r in flagged:
                print(f"  Template {r['template_id']}: {r['reason']}")
    db.close()


def export_yaml(output_path: str) -> None:
    """Export analysis results as a YAML lookup file keyed by content hash."""
    db = get_db()
    rows = db.execute(f"""
        SELECT ct.content_hash, ar.verdict, ar.model_family, ar.attack_stage,
               ar.threat_categories, ar.reason
        FROM {RESULTS_TABLE} ar
        JOIN chat_templates ct ON ct.id = ar.template_id
    """).fetchall()
    db.close()

    templates = {}
    for r in rows:
        templates[r["content_hash"]] = {
            "verdict": r["verdict"],
            "model_family": r["model_family"],
            "attack_stage": r["attack_stage"],
            "threat_categories": json.loads(r["threat_categories"] or "[]"),
            "reason": r["reason"],
        }

    out = Path(output_path)
    with open(out, "w") as f:
        yaml.dump(
            {"version": ANALYSIS_SCHEMA_VERSION, "templates": templates},
            f,
            default_flow_style=False,
            sort_keys=False,
            width=120,
        )

    from collections import Counter

    counts = Counter(t["verdict"] for t in templates.values())
    parts = ", ".join(f"{v}: {c}" for v, c in counts.most_common())
    print(f"Exported {len(templates)} templates to {out} ({parts})")


def main():
    parser = argparse.ArgumentParser(description="Batch analyze GGUF chat templates")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("submit", help="Submit batch for analysis")
    status_p = sub.add_parser("status", help="Check batch status")
    status_p.add_argument("batch_id")
    results_p = sub.add_parser("results", help="Retrieve and store results")
    results_p.add_argument("batch_id")
    sub.add_parser("run", help="Submit, poll, and store results")
    export_p = sub.add_parser("export", help="Export results as YAML lookup file")
    export_p.add_argument(
        "-o", "--output", default="template_verdicts.yaml", help="Output file path (default: template_verdicts.yaml)"
    )

    args = parser.parse_args()

    if args.command == "export":
        export_yaml(args.output)
        return

    client = anthropic.Anthropic()

    if args.command == "submit":
        db = get_db()
        templates = load_templates(db)
        db.close()
        if not templates:
            print("No unanalyzed templates found.")
            return
        submit_batch(client, templates)
    elif args.command == "status":
        check_status(client, args.batch_id)
    elif args.command == "results":
        retrieve_results(client, args.batch_id)
    elif args.command == "run":
        run_full(client)


if __name__ == "__main__":
    main()
