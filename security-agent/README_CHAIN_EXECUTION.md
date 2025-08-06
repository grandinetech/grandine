# Security Audit Chain Execution Guide

## Quick Start

### 1. Basic Execution (Recommended)

Execute the complete security audit workflow:

```bash
# In Claude Code interface
/security-audit-chain
```

This will automatically:
- Analyze project documentation
- Perform 3 rounds of code inspection
- Generate PoCs for vulnerabilities
- Create a comprehensive security report

### 2. Manual Orchestration

Use the orchestrator agent directly:

```bash
Task(
  description="Execute security audit workflow",
  prompt="Coordinate security analysis for the project at ../target-project",
  subagent_type="orchestrator-agent"
)
```

### 3. Individual Phase Execution

Execute specific phases:

```bash
# Phase 1: Specification Analysis
Task(
  description="Analyze project specs",
  prompt="Generate security specifications for ../target-project",
  subagent_type="specification-agent"
)

# Phase 2: Code Inspection
Task(
  description="Inspect code",
  prompt="Perform security code inspection using outputs/WHITEHAT_01_SPEC.json",
  subagent_type="code-inspector-agent"
)

# Phase 3: PoC Generation
Task(
  description="Create PoCs",
  prompt="Generate proof-of-concept tests for vulnerabilities in WHITEHAT_02_AUDITMAP.json",
  subagent_type="poc-generator-agent"
)

# Phase 4: Report Generation
Task(
  description="Build report",
  prompt="Create security report from audit results",
  subagent_type="report-builder-agent"
)
```

## Environment Setup

Before execution, configure:

```bash
# Required environment variables
export SOURCE_PATH="/path/to/target/project"
export TARGET_DIRECTORY="/path/to/target/project"
export DOCUMENT_DIRECTORY="/path/to/target/project/docs"

# Optional
export OUTPUT_DIRECTORY="./outputs"
export MAX_PARALLEL_AGENTS="3"
```

## Execution Options

### Parallel Execution
Run multiple PoC generations simultaneously:

```bash
/security-audit-chain --parallel-poc --max-workers 5
```

### Resume Failed Workflow
Continue from last checkpoint:

```bash
/security-audit-chain --resume
```

### Custom Output Directory
Specify output location:

```bash
/security-audit-chain --output ./custom-outputs
```

## Monitoring Progress

### Check Workflow Status
```bash
cat .workflow_state.json
```

### View Real-time Logs
```bash
tail -f outputs/workflow.log
```

### List Generated Files
```bash
ls -la outputs/
```

## Troubleshooting

### Common Issues

1. **Agent Not Found**
   ```
   Error: Unknown subagent type
   ```
   Solution: Ensure all subagent files exist in `.claude/subagents/`

2. **Phase Dependencies Failed**
   ```
   Error: Required input file not found
   ```
   Solution: Check previous phase outputs or run with `--skip-validation`

3. **Timeout Errors**
   ```
   Error: Phase exceeded timeout
   ```
   Solution: Increase timeout with `--timeout 60m` or break into smaller tasks

### Debug Mode

Enable verbose logging:

```bash
/security-audit-chain --debug --verbose
```

## Advanced Usage

### Custom Chain Definition

Create your own chain:

```yaml
# my-custom-chain.yaml
workflow_name: quick_security_scan
phases:
  - specification-agent
  - code-inspector-agent
  - report-builder-agent
```

Execute:
```bash
/security-audit-chain --config my-custom-chain.yaml
```

### Conditional Execution

Skip phases based on conditions:

```bash
# Skip PoC generation if no high-severity findings
/security-audit-chain --skip-poc-if-no-high
```

### Integration with CI/CD

```yaml
# .github/workflows/security-audit.yml
- name: Run Security Audit
  run: |
    claude-code --command "/security-audit-chain --ci-mode"
```

## Best Practices

1. **Pre-flight Checks**
   - Ensure target directory exists
   - Verify documentation is available
   - Check disk space for outputs

2. **Incremental Analysis**
   - Start with specification phase
   - Review results before proceeding
   - Adjust parameters as needed

3. **Resource Management**
   - Monitor memory usage
   - Set appropriate timeouts
   - Use parallel execution wisely

4. **Result Validation**
   - Review each phase output
   - Verify PoCs compile
   - Check report completeness