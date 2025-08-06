# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security-agent is a Python-based security analysis tool designed for Bug Bounty research and vulnerability assessment in blockchain projects. It combines static code analysis with AI-powered agents using OpenAI's GPT-4o to perform comprehensive security audits.

## Core Architecture

### Key Components

1. **Static Analysis Engine** (`utils/static_analyzer.py`)
   - Analyzes Solidity and JavaScript codebases
   - Generates AST and call graphs
   - Plugin-based architecture for language support

2. **AI Agent System** (`utils/utils.py`)
   - DeepResearchRunner: GPT-4o with WebSearch for analyzing bug bounty scopes
   - AgentRunner: Base class for JSON-extracting agents
   - Multi-phase security analysis workflow

3. **Plugin System** (`utils/plugins/`)
   - SolidityPlugin: Uses Slither for smart contract analysis
   - JavaScriptPlugin: AST parsing for JS/TS files

4. **Prompt Templates** (`prompts/`)
   - Structured templates for attacker and whitehat perspectives
   - Phase-based analysis (SPEC → CODE_INSPECTOR → ATTACK_SCENARIOS → POC → REPORT)

## Development Commands

### Environment Setup
```bash
# Install dependencies using uv package manager
uv sync

# Create .env file from example
cp .env.example .env
# Configure: SOURCE_PATH, TARGET_DIRECTORY, DOCUMENT_DIRECTORY
```

### Static Analysis
```bash
# Analyze a repository
uv run python -m utils.static_analyzer <path_to_repo> --verbose

# Example: analyze parent directory
uv run python -m utils.static_analyzer .. --verbose
```

### Visualization
```bash
# Generate call graphs (requires Graphviz installed)
cd outputs/callgraphs

# PNG for viewing
dot -Tpng <contract>.call-graph.dot -o <contract>.png

# SVG for interactive exploration
dot -Tsvg all_contracts.call-graph.dot -o all_contracts.svg

# PDF for documentation
dot -Tpdf <contract>.call-graph.dot -o <contract>.pdf
```

### Testing & Quality
```bash
# Note: No testing framework currently configured
# When adding tests, consider using pytest

# No linting tools configured
# Consider adding: ruff, mypy, or flake8
```

## Project Structure

- `/prompts/`: AI agent prompt templates for security analysis phases
- `/docs/`: Security knowledge base (bug reports, attack patterns, checklists)
- `/utils/`: Core analysis tools and plugins
- `/outputs/`: Generated analysis results (gitignored)
  - `00_AST.json`: Abstract syntax tree data
  - `00_callgraph.json`: Call graph relationships
  - `/callgraphs/`: DOT files for visualization

## Security Analysis Workflow

The tool follows a structured approach documented in `docs/whitehat_workflow.md`:

1. Information Gathering & Specification Analysis
2. Structure Mapping (with @audit flags)
3. Deep Verification (PoC creation)
4. Known Pattern Matching
5. Composability Risk Assessment
6. Economic Feasibility Analysis
7. Report Integration & Learning Feedback
8. Final Review & Responsible Disclosure

## Working with AI Agents

The system uses specialized agents for different analysis phases:
- **Specification Agent**: Analyzes project documentation and scope
- **Code Inspector**: Maps codebase structure and identifies critical areas
- **Attack Scenario Agent**: Generates potential attack vectors
- **PoC Agent**: Creates proof-of-concept exploits
- **Report Agent**: Compiles findings into structured reports

## Important Notes

- This is a defensive security tool for authorized Bug Bounty research
- Always ensure you have permission before analyzing external codebases
- The tool generates sensitive security findings - handle outputs carefully
- Requires Graphviz for visualization features
- Uses OpenAI API - ensure API keys are properly configured

## Prompt Guidelines

- これらのプロンプトは審査対象のディレクトリ内での運用を想定しています