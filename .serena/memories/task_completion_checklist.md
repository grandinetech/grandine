# Task Completion Checklist

When completing any development task in the Grandine project, ensure you follow these steps:

## 1. Code Quality Checks

### Rust Code
- [ ] Run `cargo fmt` to format code
- [ ] Run `cargo fmt --check` to verify formatting
- [ ] Run `scripts/ci/clippy.bash --deny warnings` to check for linting issues
- [ ] Run `cargo test` to ensure all tests pass
- [ ] Run `cargo build` to ensure code compiles without errors

### Python Code (Security Agent)
- [ ] No specific linting/formatting tools configured
- [ ] Consider adding: ruff, mypy, or flake8 for future development
- [ ] Ensure code follows established patterns in existing files

## 2. Testing
- [ ] Run relevant unit tests: `cargo test --release`
- [ ] For specific features: `cargo test --release --no-default-features --features <feature>`
- [ ] On macOS, skip network tests if needed: `-- --skip behaviour --skip common`
- [ ] Verify no regressions in existing functionality

## 3. Documentation
- [ ] Update relevant documentation if behavior changes
- [ ] Add comments for complex logic (in English)
- [ ] Ensure CLAUDE.md is updated if development workflow changes

## 4. Git Workflow
- [ ] Create feature branch (never commit to main/develop directly)
- [ ] Make atomic commits with clear messages
- [ ] Push to remote: `git push -u origin <branch-name>`
- [ ] Create Pull Request using GitHub CLI or web interface
- [ ] Ensure CI checks pass

## 5. Security Considerations
- [ ] No unsafe code added (enforced by linter)
- [ ] No secrets or keys in code
- [ ] Use secure coding practices
- [ ] For security analysis: ensure authorized access to target code

## 6. Performance Considerations
- [ ] Consider memory usage (Grandine targets ~2.5GB on mainnet)
- [ ] Ensure changes don't negatively impact performance
- [ ] Profile if making performance-critical changes

## Important Notes
- Always run formatting and linting before committing
- Tests must pass before creating PR
- Follow existing code patterns and conventions
- When in doubt, check how similar functionality is implemented elsewhere in the codebase