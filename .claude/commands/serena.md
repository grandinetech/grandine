---
allowed-tools: Read, Glob, Grep, Edit, MultiEdit, Write, Bash, TodoWrite, mcp__serena__check_onboarding_performed, mcp__serena__delete_memory, mcp__serena__find_file, mcp__serena__find_referencing_symbols, mcp__serena__find_symbol, mcp__serena__get_symbols_overview, mcp__serena__insert_after_symbol, mcp__serena__insert_before_symbol, mcp__serena__list_dir, mcp__serena__list_memories, mcp__serena__onboarding, mcp__serena__read_memory, mcp__serena__remove_project, mcp__serena__replace_regex, mcp__serena__replace_symbol_body, mcp__serena__restart_language_server, mcp__serena__search_for_pattern, mcp__serena__switch_modes, mcp__serena__think_about_collected_information, mcp__serena__think_about_task_adherence, mcp__serena__think_about_whether_you_are_done, mcp__serena__write_memory, mcp__context7__resolve-library-id, mcp__context7__get-library-docs
description: Token-efficient Serena MCP command for structured app development and problem-solving
---

## Quick Reference

```bash
/serena <problem> [options]           # Basic usage
/serena debug "memory leak in prod"   # Debug pattern (5-8 thoughts)
/serena design "auth system"          # Design pattern (8-12 thoughts)  
/serena review "optimize this code"   # Review pattern (4-7 thoughts)
/serena implement "add feature X"     # Implementation (6-10 thoughts)
```

## Options

| Option | Description | Usage | Use Case |
|--------|-------------|-------|----------|
| `-q` | Quick mode (3-5 thoughts/steps) | `/serena "fix button" -q` | Simple bugs, minor features |
| `-d` | Deep mode (10-15 thoughts/steps) | `/serena "architecture design" -d` | Complex systems, major decisions |
| `-c` | Code-focused analysis | `/serena "optimize performance" -c` | Code review, refactoring |
| `-s` | Step-by-step implementation | `/serena "build dashboard" -s` | Full feature development |
| `-v` | Verbose output (show process) | `/serena "debug issue" -v` | Learning, understanding process |
| `-r` | Include research phase | `/serena "choose framework" -r` | Technology decisions |
| `-t` | Create implementation todos | `/serena "new feature" -t` | Project management |

## Usage Patterns

### Basic Usage
```bash
# Simple problem solving
/serena "fix login bug"

# Quick feature implementation  
/serena "add search filter" -q

# Code optimization
/serena "improve load time" -c
```

### Advanced Usage
```bash
# Complex system design with research
/serena "design microservices architecture" -d -r -v

# Full feature development with todos
/serena "implement user dashboard with charts" -s -t -c

# Deep analysis with documentation
/serena "migrate to new framework" -d -r -v --focus=frontend
```

## Context (Auto-gathered)
- Project files: !`find . -maxdepth 2 -name "package.json" -o -name "*.config.*" | head -5 2>/dev/null || echo "No config files"`
- Git status: !`git status --porcelain 2>/dev/null | head -3 || echo "Not git repo"`

## Core Workflow

### 1. Problem Detection & Template Selection
Automatically select thinking pattern based on keywords:
- **Debug**: error, bug, issue, broken, failing → 5-8 thoughts
- **Design**: architecture, system, structure, plan → 8-12 thoughts  
- **Implement**: build, create, add, feature → 6-10 thoughts
- **Optimize**: performance, slow, improve, refactor → 4-7 thoughts
- **Review**: analyze, check, evaluate → 4-7 thoughts

### 2. MCP Selection & Execution
```
App Development Tasks → Serena MCP
- Component implementation
- API development
- Feature building
- System architecture

All Tasks → Serena MCP
- Component implementation
- API development 
- Feature building
- System architecture
- Problem solving and analysis
```

### 3. Output Modes
- **Default**: Key insights + recommended actions
- **Verbose (-v)**: Show thinking process
- **Implementation (-s)**: Create todos + start execution

## Problem-Specific Templates

### Debug Pattern (5-8 thoughts)
1. Symptom analysis & reproduction
2. Error context & environment check  
3. Root cause hypothesis generation
4. Evidence gathering & validation
5. Solution design & risk assessment
6. Implementation plan
7. Verification strategy
8. Prevention measures

### Design Pattern (8-12 thoughts)  
1. Requirements clarification
2. Constraints & assumptions
3. Stakeholder analysis
4. Architecture options generation
5. Option evaluation (pros/cons)
6. Technology selection
7. Design decisions & tradeoffs
8. Implementation phases
9. Risk mitigation
10. Success metrics
11. Validation plan
12. Documentation needs

### Implementation Pattern (6-10 thoughts)
1. Feature specification & scope
2. Technical approach selection
3. Component/module design
4. Dependencies & integration points
5. Implementation sequence
6. Testing strategy
7. Edge case handling
8. Performance considerations
9. Error handling & recovery
10. Deployment & rollback plan

### Review/Optimize Pattern (4-7 thoughts)
1. Current state analysis
2. Bottleneck identification
3. Improvement opportunities
4. Solution options & feasibility
5. Implementation priority
6. Performance impact estimation
7. Validation & monitoring plan

## Advanced Options

**Thought Control:**
- `--max-thoughts=N`: Override default thought count
- `--focus=AREA`: Domain-specific analysis (frontend, backend, database, security)
- `--token-budget=N`: Optimize for token limit

**Integration:**
- `-r`: Include Context7 research phase
- `-t`: Create implementation todos
- `--context=FILES`: Analyze specific files first

**Output:**
- `--summary`: Condensed output only
- `--json`: Structured output for automation
- `--progressive`: Show summary first, details on request

## Task Execution

You are an expert app developer and problem-solver primarily using Serena MCP. For each request:

1. **Auto-detect problem type** and select appropriate approach
2. **Use Serena MCP**:
   - **All development tasks**: Use Serena MCP tools (https://github.com/oraios/serena)
   - **Analysis, debugging, implementation**: Use Serena's semantic code tools
3. **Execute structured approach** with chosen MCP
4. **Research relevant docs** with Context7 MCP if needed
5. **Synthesize actionable solution** with specific next steps
6. **Create implementation todos** if `-s` flag used

**Key Guidelines:**
- **Primary**: Use Serena MCP tools for all tasks (components, APIs, features, analysis)
- **Leverage**: Serena's semantic code retrieval and editing capabilities
- Start with problem analysis, end with concrete actions
- Balance depth with token efficiency
- Always provide specific, actionable recommendations
- Consider security, performance, and maintainability

**Token Efficiency Tips:**
- Use `-q` for simple problems (saves ~40% tokens)
- Use `--summary` for overview-only needs  
- Combine related problems in single session
- Use `--focus` to avoid irrelevant analysis
