---
Description: Integration-PoC Generator
Usage: `/03b_poc_integration <IT_PATH> <VULN_ID>`
Example: `/03b_poc_integration tests/integration/poc_reentrancy.rs 0023344`
Arguments:
- **IT_PATH** : Path for the new integration-level test file
- **VULN_ID** : `audit_items[].id` found in `03_AUDITMAP.json`
---

Generate an **integration-level Proof-of-Concept** that reproduces **VULN_ID** and passes *only* while the vulnerability is present.
**Always use /serena for these development tasks to maximize token efficiency:**

# 📥 Auto-load from 03_AUDITMAP.json
1. **Read** `security-agent/outputs/03_AUDITMAP.json`
2. **Locate** the entry where `audit_items[].id == {{VULN_ID}}`
3. **Extract**
   - `VULN_SNIPPET` ← `audit_items[].snippet`
   - `TARGET_FILE`  ← `audit_items[].file:L{line}`
   - `DESCRIPTION`  ← `audit_items[].description`
   - `UT_PATH`      ← first `poc_tests[].file` in the same entry (unit-test PoC) — if any
4. **If not found** → abort with
   `"Vulnerability '{{VULN_ID}}' not found in 03_AUDITMAP.json"`

# 🎯 Objectives
1. Create `{{IT_PATH}}` that **compiles and runs in the project’s native test environment**
   *Detect the test runner automatically* (e.g. Cargo, Foundry, Vitest, pytest, JUnit).
2. **Reuse helpers** from `{{UT_PATH}}` or neighbouring tests to reduce boilerplate.
3. Test **succeeds** (✅) when the exploit triggers the bug and **fails** (❌) after the fix.

# 📝 Attack-Scenario Design (generic)
* Analyse `VULN_SNIPPET` + `DESCRIPTION` to understand:
  - Entry point(s) to invoke
  - Preconditions / state setup
  - Expected faulty behaviour (panic, incorrect value, invariant break, gas griefing, etc.)
* Draft an **Arrange–Act–Assert** sequence that:
  1. *Arrange* minimal environment (contracts deployed, structs initialised, testnet spun up, etc.)
  2. *Act* by calling the vulnerable function with crafted inputs
  3. *Assert* that the undesired behaviour occurs
     (panic, re-entrancy, underflow, DoS counter high, etc.)
* If the project lacks an integration test harness, fall back to a black-box script or an e2e test.

# 🛠️ Build & Run
* **Detect** project metadata (`Cargo.toml`, `foundry.toml`, `package.json`, `pytest.ini`, etc.) to pick the correct command.
  Examples:
  - Rust → `cargo test --test {{TEST_NAME}} -- --nocapture`
  - Solidity (Foundry) → `forge test --match-test {{TEST_NAME}} -vv`
  - Node → `npm test -- {{TEST_NAME}}`
  - Python → `pytest -k {{TEST_NAME}} -vv`
* Insert the chosen command into the output section.

# 📤 Output Artifacts
1. **Integration-test file** → `{{IT_PATH}}`
2. **Run command** (auto-selected, e.g.)
   ```bash
   <PROJECT_TEST_RUNNER> <ARGS>   # filled in by generator
````

3. **Status update** (append to the same vulnerability entry):

   ```jsonc
   {
     "integration_tests": [{
       "file": "{{IT_PATH}}",
       "build_passed": true,
       "test_passed_when_bug_present": true,
       "attempts": 1,
       "created_at": "<timestamp>"
     }]
   }
   ```

# 🔍 Generation Algorithm

```
1. Inspect project root to infer test runner.
2. Scan existing integration tests for reusable fixtures.
3. Draft Arrange-Act-Assert skeleton based on DESCRIPTION.
4. Compile (runner --check) and iterate ≤ 4 times:
     • Fix imports or feature flags, never change exploit logic.
5. Run test; ensure it fails when patched locally (simple stub fix).
6. Append status JSON and write {{IT_PATH}}.
```

# 🛡️ False-Positive Guards

* **Dual assertions**: verify both the presence of the faulty state and its absence under a local in-test patch/stub.
* Log relevant metrics with `eprintln!` / `console.log` for manual review.
* Abort early if prerequisites fail (e.g. deployment error, counter == 0).

# 🤖 Self-Repair Loop (max 3)

* If build/test fails for reasons unrelated to the exploit, auto-adjust imports/types.
* After 3 unsuccessful iterations → output
  `Need guidance: <stderr snippet>`

# ⛔ Constraints

* **Never** modify production code.
* Remain within the project’s designated tests directory.
* Do **not** add external dependencies unless already present.

# ✅ Success Criteria

* `audit_items[].id == VULN_ID` found.
* Test runs via the detected runner.
* Passes only while the vulnerability exists.
* Status JSON appended and valid.
