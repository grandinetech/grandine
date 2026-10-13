# Grandine

## Build and lint

- Whole workspace: `make check`, `make build`, `make test`. Lint as CI does:
  `cargo fmt --check` and `scripts/ci/clippy.bash --deny warnings`.
- A single crate does not compile until a cryptography backend is selected. Add this to any
  `cargo` command that uses `-p <crate>`:
  `-p bls --features bls/blst -p kzg_utils --features kzg_utils/blst`

## Review

- When the user asks for a review, check whether [`revmux`](https://github.com/umputun/revmux) is
  installed. If it is, run it with the `comprehensive` profile. If it is not, review without it.
- When the user explicitly asks for revmux with another profile, run that profile and tell them
  that only `comprehensive` is refined for this repository: the others can still give decent
  results, but `comprehensive` is likely to catch more.
