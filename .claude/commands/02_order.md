---
Description: Generate an ordered audit map for security review of a specific target folder.
Usage: `/02_order <TARGET_FOLDER>`
Arguments:
- TARGET_FOLDER: The folder path to analyze (relative to the project root)
---
Generate 02_ORDER.json from the sources
**Always use /serena for these development tasks to maximize token efficiency:**


# 🎯 Goal
Produce an *ordered* audit map covering **every function** in `{{TARGET_FOLDER}}`, so that a
security reviewer can progress from outer‑surface attack vectors to deeper
trust anchors while naturally uncovering hierarchical defences.

# 📥 Input
1.  **Folder:** `{{TARGET_FOLDER}}` (recursively include sub‑modules / packages).
2.  **Static call‑graph (optional):** `{{STATIC_CALLGRAPH}}`
    - If set to `NONE`, derive call relationships yourself.
3.  **Project specification:**
    `security-agent/outputs/01_SPEC.json`
4.  **Ethereum canonical specs:**
    `security-agent/docs/ethereum/spec_*.json` (multiple files, merge).

# 📤 Output
Create **one** JSON file:
`security-agent/outputs/02_ORDER.json`

```jsonc
{
  "metadata": {
    "target_folder": "{{TARGET_FOLDER}}",
    "static_callgraph": "{{STATIC_CALLGRAPH}}",
    "spec_loaded": true,
    "generated_at": "<RFC3339 timestamp>",
    "schema_version": "1.0.0"
  },
  "audit_chunks": [
    {
      "chunk_title": "🚪 External entry points ― network packet handlers",
      "rationale": "First code reached by untrusted input; high‑risk for RCE / DoS",
      "functions": [
        {"name": "handle_packet", "file": "src/handler.rs", "line": 42},
        {"name": "parse_header", "file": "src/parser.rs", "line": 10}
      ]
    },
    {
      "chunk_title": "🔐 Cryptographic verification",
      "rationale": "Critical for authenticity; breaks compromise confidentiality",
      "functions": [ ... ]
    }
    // …すべての関数がいずれかのチャンクに登場するまで続く …
  ],
  "top_attack_paths": [
    {
      "entry_function": "handle_packet",
      "sink_function": "commit_state",
      "risk_reason": "Untrusted input → state mutation without full validation"
    }
    // 最低 3 経路
  ],
  "ordering_strategy": "Breadth‑first from untrusted boundaries inward, guided by call‑graph depth and STRIDE‑like risk categories (S,T,R,I,D,E)."
}
````

**Constraints**

* Every function in `{{TARGET_FOLDER}}` **must appear exactly once** in
  `audit_chunks[*].functions`.
* Preserve source order within each chunk **only** if no call‑graph info exists;
  otherwise sort by caller‑depth (roots first).
* Maximum functions per chunk: **12** (split logically if exceeded).
* Use ✨ Unicode emojis in `chunk_title` to telegraph threat class (optional but preferred).

# 🛠️ Methodology

1. **Load specs** → extract trust boundaries, privilege tiers, security‑critical
   components.
2. If `STATIC_CALLGRAPH` ≠ NONE
   → merge its edges into an in‑memory graph; verify completeness; fill gaps
   via on‑the‑fly parsing.
3. Else
   → parse *all* source files; build call‑graph (ignore std lib edges).
4. Compute node depth; tag entry points (extern "C", public API, CLI, RPC,
   interrupt handlers, etc.).
5. Prioritise chunks:

   1. Untrusted data entry (network / disk / IPC).
   2. Privilege‑escalation or crypto‑verification.
   3. State‑mutation hubs.
   4. Low‑level utilities & pure helpers.
6. Within a chunk, list functions **caller‑before‑callee** for natural read‑flow.
7. Build `top_attack_paths` by traversing shortest paths from entry nodes to any
   state‑changing sinks with insufficient checks.
8. Validate final JSON (no duplicate functions, valid RFC3339 timestamp).
9. **Write** the file and return *nothing* else.

# 📚 Quality levers

* Multi‑pass reflection: draft → consistency check → final rewrite.
* Keep explanations concise (< 60 words per `rationale`).
* Use internal chain‑of‑thought; expose only final JSON.
* Fail fast on schema errors; retry once after auto‑fix.

# ✅ Success criteria

* File exists; JSON parsable.
* 100 % of functions covered; zero duplicates.
* Chunk sequence moves logically from attack surface to core.
* ≥ 3 attack paths provided, each plausible and source‑linked.
