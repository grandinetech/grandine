# Security Analysis Chain Flow Template

This template demonstrates how to chain security subagents for comprehensive vulnerability analysis.

## Flow Definition

```yaml
workflow_name: comprehensive_security_audit
description: Complete security analysis workflow using chained subagents
output_directory: outputs/security_audit_{timestamp}

phases:
  - phase_1_specification:
      agent: specification-agent
      inputs:
        target_directory: ${TARGET_DIRECTORY}
        document_directory: ${DOCUMENT_DIRECTORY}
      outputs:
        - WHITEHAT_01_SPEC.json
      validation:
        - metadata.source_directory must exist
        - architecture section must be populated
        - at least 3 user_flows defined
      
  - phase_2_code_inspection:
      agent: code-inspector-agent
      depends_on: phase_1_specification
      iterations: 3  # Run multiple rounds for thorough analysis
      inputs:
        spec_file: ${phase_1_specification.outputs[0]}
        source_directory: ${TARGET_DIRECTORY}
        round: ${iteration_number}
      outputs:
        - WHITEHAT_02_AUDITMAP_R${iteration_number}.json
      validation:
        - audit_items array must have entries
        - each item must have valid risk_category
        - snippet must be non-empty
      
  - phase_3_poc_generation:
      agent: poc-generator-agent
      depends_on: phase_2_code_inspection
      parallel: true  # Run PoC generation for multiple findings in parallel
      foreach: ${phase_2_code_inspection.outputs.audit_items[status=Vuln]}
      inputs:
        audit_item: ${item}
        source_directory: ${TARGET_DIRECTORY}
        test_framework: auto_detect
      outputs:
        - tests/security/poc_${item.risk_category}_${item.line}.test
      validation:
        - test file must compile
        - test must demonstrate vulnerability
      
  - phase_4_report_generation:
      agent: report-builder-agent
      depends_on: [phase_2_code_inspection, phase_3_poc_generation]
      inputs:
        audit_maps: ${phase_2_code_inspection.outputs}
        poc_tests: ${phase_3_poc_generation.outputs}
        template: prompts/bug_bounty_report_template.md
      outputs:
        - SECURITY_REPORT_${timestamp}.md
      validation:
        - no placeholders remaining
        - all sections populated
        - severity ratings justified
```

## Usage Example

```bash
# Using the orchestrator agent to execute the chain
Task(
  description="Execute security audit workflow",
  prompt="/security-audit-chain --target ../target-project --docs ../target-project/docs",
  subagent_type="orchestrator-agent"
)
```

## Chaining Patterns

### Sequential Chain
Each phase depends on the previous phase's output:
```
specification → code_inspection → poc_generation → report
```

### Iterative Chain
Run the same agent multiple times with different inputs:
```
code_inspection_round_1 → code_inspection_round_2 → code_inspection_round_3
```

### Parallel Chain
Run multiple instances for different items:
```
poc_generation[vuln1] ⟶
poc_generation[vuln2] ⟶ report_generation
poc_generation[vuln3] ⟶
```

### Conditional Chain
Execute based on conditions:
```yaml
- conditional_phase:
    condition: ${phase_2.audit_items.length > 0}
    if_true: poc-generator-agent
    if_false: skip_to_report
```

## Error Handling

```yaml
error_handling:
  retry_policy:
    max_attempts: 3
    backoff_multiplier: 2
    retry_on: [timeout, api_error]
  
  fallback_chain:
    on_specification_failure: manual_specification_input
    on_code_inspection_failure: simplified_grep_analysis
    on_poc_failure: theoretical_poc_description
    on_report_failure: raw_findings_export
```

## Progress Tracking

```yaml
progress_tracking:
  update_interval: after_each_phase
  notifications:
    - on_phase_complete: log_to_file
    - on_error: alert_user
    - on_workflow_complete: generate_summary
  
  state_persistence:
    checkpoint_after: each_phase
    resume_capability: true
    state_file: .workflow_state.json
```

## Advanced Features

### Data Transformation Between Phases
```yaml
transformations:
  - between: [phase_1, phase_2]
    transform: |
      extract_critical_functions(spec.architecture) → audit_order.json
  
  - between: [phase_2, phase_3]
    transform: |
      filter(audit_items, item => item.status === "Vuln" && item.risk_category !== "Info")
```

### Dynamic Agent Selection
```yaml
dynamic_selection:
  - for: code_inspection
    select_agent_based_on:
      solidity_files: "solidity-inspector-agent"
      javascript_files: "javascript-inspector-agent"
      mixed_codebase: "code-inspector-agent"
```

### Resource Management
```yaml
resources:
  max_parallel_agents: 3
  memory_limit_per_agent: "2GB"
  timeout_per_phase: "30m"
  preserve_intermediate_outputs: true
```

## Integration with Existing Tools

```yaml
external_integrations:
  - pre_workflow:
      - run: "git pull origin main"
      - run: "npm install"
      - run: "foundry build"
  
  - post_workflow:
      - upload_to: "bug_bounty_platform"
      - notify: "security_team@example.com"
      - archive: "s3://security-audits/${workflow_id}"
```

## Monitoring and Metrics

```yaml
metrics:
  collect:
    - phase_duration
    - findings_per_phase
    - poc_success_rate
    - total_vulnerabilities_by_severity
  
  export_to:
    format: json
    path: metrics/audit_${timestamp}.json
```
