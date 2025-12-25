# Validate GitHub Actions Workflows

## Purpose
Validate and test GitHub Actions workflows to ensure they're properly configured and will work correctly.

## Process

### 1. Check Workflow Files Exist

```bash
# Check which repos have workflows
find . -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" | grep -v node_modules | sort
```

### 2. Validate Workflow Syntax

```bash
# Install act if not already installed (already installed per user)
# brew install act

# List workflows in current repo
act -l

# Validate workflow syntax (dry run)
act -n -W .github/workflows/ci.yml
```

### 3. Test Workflows Locally with act

```bash
# Test CI workflow
act push -W .github/workflows/ci.yml

# Test specific job
act -j test -W .github/workflows/ci.yml

# Test with pull_request event
act pull_request -W .github/workflows/ci.yml

# Test release workflow (requires secrets)
act push -e .github/workflows/release.yml --secret-file .secrets
```

### 4. Check for Common Issues

- [ ] **Action versions**: Are they using latest versions?
  - `actions/checkout@v4` (not v3)
  - `actions/setup-node@v4` (not v3)
  - `actions/setup-python@v5` (not v4)
  - `actions/cache@v4` (not v3)

- [ ] **Permissions**: Are they set appropriately?
  ```yaml
  permissions:
    contents: write  # For releases
    pull-requests: write  # For PR creation
  ```

- [ ] **Caching**: Are dependencies cached?
  - Rust: `target/` and cargo registry
  - Node: `cache: 'npm'` or `cache: 'pnpm'`
  - Python: `cache: 'pip'`

- [ ] **Secrets**: Are they using GitHub Secrets (not hardcoded)?

- [ ] **Triggers**: Are they appropriate?
  - CI: `push` and `pull_request`
  - Release: `push: tags: ['v*']`
  - Sync: `schedule` and `workflow_dispatch`

### 5. Repository-Specific Checks

#### beltic-cli
- [ ] CI workflow tests, lints, builds
- [ ] Release workflow builds for all platforms (macOS arm64/x86_64, Linux arm64/x86_64)
- [ ] Sync schemas workflow exists

#### beltic-sdk
- [ ] CI workflow tests, lints, type-checks, builds
- [ ] Release workflow uses semantic-release
- [ ] Sync schemas workflow regenerates TypeScript types

#### fact-python
- [ ] CI workflow tests on Python 3.10, 3.11, 3.12
- [ ] Release workflow publishes to PyPI
- [ ] Sync schemas workflow exists

#### beltic-spec
- [ ] Validate workflow validates schemas and examples
- [ ] Both Node.js and Python validation jobs

#### wizard
- [ ] Build workflow exists
- [ ] Publish workflow exists
- [ ] PR conventional commit validation exists

## Testing with act

### Basic Usage

```bash
# List all workflows
act -l

# Run default workflow (push event)
act

# Run specific workflow
act -W .github/workflows/ci.yml

# Run specific job
act -j test

# Run with specific event
act push
act pull_request
act workflow_dispatch
```

### Advanced Usage

```bash
# Use specific platform (default is ubuntu-latest)
act -P ubuntu-latest=catthehacker/ubuntu:act-latest

# Run with secrets
act --secret-file .secrets

# Run with environment variables
act -e .env

# Show verbose output
act -v

# Dry run (don't actually run)
act -n
```

### Creating .secrets File

For testing workflows that require secrets:

```bash
# Create .secrets file (add to .gitignore!)
cat > .secrets <<EOF
GITHUB_TOKEN=your_token_here
NPM_TOKEN=your_npm_token_here
PYPI_API_TOKEN=your_pypi_token_here
EOF

# Add to .gitignore
echo ".secrets" >> .gitignore
```

## Common Issues and Fixes

### Issue: Workflow fails locally but works on GitHub
- **Fix**: Check if using `act` with correct platform image
- **Fix**: Ensure secrets are properly configured

### Issue: Cache not working
- **Fix**: Verify cache key includes hash of lock file
- **Fix**: Check cache paths are correct

### Issue: Permissions denied
- **Fix**: Add appropriate permissions to workflow
- **Fix**: Check if using correct token (GITHUB_TOKEN vs custom token)

### Issue: Action version outdated
- **Fix**: Update to latest version (check action's releases)

## Notes

- `act` is already installed on this system
- Use `act -n` for dry runs to validate syntax
- Test workflows locally before pushing
- Keep `.secrets` file in `.gitignore`
- Some workflows may not run perfectly with act (especially release workflows)

