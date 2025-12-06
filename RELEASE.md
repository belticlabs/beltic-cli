# Release Process

Lightweight checklist for publishing a Beltic CLI release.

## Prepare
- Ensure a clean working tree on `master`.
- Verify `Cargo.toml`/`Cargo.lock` carry the target version (e.g., `0.1.2`).
- Run quality gates: `cargo fmt --all`, `cargo clippy --all-targets --all-features -D warnings`, `cargo test --all`.

## Tag and push
- Draft notes from recent commits: `git log $(git describe --tags --abbrev=0)..HEAD --oneline`.
- Create an annotated tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"` (match the Cargo version).
- Push the tag: `git push origin vX.Y.Z`.

## Publish
- Build once locally for sanity: `cargo build --release`.
- Create the GitHub release (after CI artifacts are ready) with notes and checksums if applicable, e.g.:
  - `gh release create vX.Y.Z --generate-notes` or publish via the GitHub UI.
- Verify `install.sh` resolves the new release asset and that download/install succeeds end-to-end.

## Release notes (v0.1.2)
- New `sandbox` command for pre-deployment runs with manifest-derived policy enforcement and JSON reports.
- Auto-discovery defaults for signing and verification flows to reduce required flags.
- Schema and credential helpers: `schema` cache management and `credential-id` extraction for JWT/JSON payloads.
- Framework detection improvements for Python/Go projects to pre-fill manifest metadata.
- Documentation cleanup: new contributor/release guides and removal of outdated SDK doc.
