---
Description: PoC Generator & Self-Verifying Test
Usage: `/03a_poc_unit <VULN_ID> <OUTPUT_TEST_PATH>`
Example: `/03a_poc_unit 03523523 crates/net/network/src/transactions/poc_reentrancy.rs`
Arguments:
- **VULN_ID**: `03_AUDITMAP.json` 内の `audit_items[].id`
- **OUTPUT_TEST_PATH**: 生成するテストファイルの保存先
---

Create & validate a minimal PoC test that reproduces **VULN_ID**
**Always use /serena for these development tasks to maximize token efficiency:**


# 📥 Auto-load from 03_AUDITMAP.json
1. **Read** `security-agent/outputs/03_AUDITMAP.json`
2. **Find** the entry where `audit_items[].id == {{VULN_ID}}`
3. **Extract**
   - `VULN_SNIPPET` ← `audit_items[].snippet`
   - `TARGET_FILE` ← `audit_items[].file` + `:L` + `audit_items[].line`
4. **If not found** → abort with error
   `"Vulnerability '{{VULN_ID}}' not found in 03_AUDITMAP.json"`

# 🎯 Goal
Produce **one Rust test file** that:
1. Compiles & runs under `cargo test` (or Foundry, if Solidity)
2. **Fails (or panics) only when the vulnerability is present**
3. Requires *no* external binaries or network deps

# 📥 Input
- Vulnerability DB:    `security-agent/outputs/03_AUDITMAP.json`
- Project spec:        `security-agent/outputs/01_SPEC.json`
- Ethereum bug corpus: `security-agent/docs/ethereum/bugs_*.json`
- Ethereum specs:      `security-agent/docs/ethereum/spec_*.json`
- Source code:         Auto-loaded `TARGET_FILE` と周辺

# 🧩 Pre-work (internal)
1. Locate exact code containing `VULN_SNIPPET`
2. Look for existing tests/mocks to reuse
3. Design exploit scenario (Arrange-Act-Assert)

# 📤 Output Artifacts
1. **PoC test file** → `{{OUTPUT_TEST_PATH}}`
2. **Run command**
   ```bash
   cargo test --test poc_{{VULN_ID}} -- --nocapture
````

3. **Status JSON** (append into same vulnerability entry)

   ```jsonc
   {
     "audit_items": [{
       // ... existing fields ...
       "poc_tests": [{
         "type": "unit",
         "file": "{{OUTPUT_TEST_PATH}}",
         "build_passed": true,
         "test_result": "pass_when_exploitable",
         "attempts": 1,
         "created_at": "<timestamp>"
       }]
     }]
   }
   ```

# 🔍 PoC Generation Algorithm

```
PLAN = global plan()
FOR attempt in 1..=4:
    generate skeleton using mocks
    if compile succeeds:
        run test
        if exploit reproduced: break ✅
    else:
        if attempt == 4: ask user 🆘
        adapt imports/types and retry
```

# 🛡️ False-Positive Mitigation

* Invariant double-check & patched-code control
* No silent `unwrap()`

# 📝 Test Style Guide

```rust
#[test]
fn poc_{{VULN_ID}}() {
    // Arrange
    /* minimal setup */

    // Act
    let res = import_transactions(/* crafted args */);

    // Assert
    assert!(matches!(res, Err(_)), "exploit succeeded");
}
```

# ⛔ Constraints

* **Do not** touch production logic
* **Do not** add new crates (unless already in Cargo.toml)
* Keep test ≤ 120 LOC

# ✅ Success Criteria

* Entry with `id == VULN_ID` found
* Test fails only when bug present
* Status JSON correctly appended
* > 3 compile failures → prompt user
