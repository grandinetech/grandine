# Code Style and Conventions

## Rust Code Style

### General Principles
- **Edition**: Rust 2021
- **Toolchain**: stable-2025-06-26
- **Safety**: `unsafe_code` is forbidden at workspace level
- **Comments**: In English only

### Formatting (rustfmt.toml)
- Unix newline style
- Use field init shorthand (`field` instead of `field: field`)
- Use try shorthand (`?` operator)
- Additional unstable formatting options available via `--config` flag

### Linting (Clippy)
- Pedantic and nursery lint groups enabled
- Extensive custom lint configuration in `clippy.toml`
- Many restriction lints enabled for code quality
- Custom disallowed methods (e.g., use `fs_err` instead of `std::fs` for better errors)
- Enforced import renames (e.g., `core::fmt::Result` as `FmtResult`)

### Key Conventions
1. **No unsafe code** - enforced at workspace level
2. **Error handling**: Use `fs_err` for filesystem operations
3. **URLs**: Use `types::redacting_url::RedactingUrl` for print-safe URLs
4. **Imports**: Follow standard grouping (std, external, internal)
5. **Type hints**: Always provide clear type annotations where helpful
6. **Documentation**: Focus on "why" rather than "what"

### Workspace Structure
- Monorepo with multiple crates in workspace
- Each crate has specific responsibility
- Dependencies managed centrally in workspace Cargo.toml
- Feature resolver version 2 used

## Python Code Style (Security Agent)

### General Principles
- Python 3.x with type hints
- Plugin-based architecture for extensibility
- Clear separation of concerns

### Structure
- Static analysis in `utils/`
- Language plugins in `utils/plugins/`
- Prompt templates in `prompts/`
- Documentation in `docs/`

### Naming Conventions
- Classes: PascalCase (e.g., `AgentRunner`, `SolidityPlugin`)
- Functions/methods: snake_case (e.g., `analyze_repository`)
- Constants: UPPER_SNAKE_CASE
- Private methods: prefix with underscore

### Key Patterns
- Abstract base classes for plugins
- JSON-based configuration and output
- Structured logging with verbose flag
- Clear error messages and handling