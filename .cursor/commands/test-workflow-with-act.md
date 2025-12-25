# Test Workflow with act

## Purpose
Test GitHub Actions workflows locally using `act` before pushing to GitHub.

## Prerequisites

- `act` is already installed on this system
- Workflow files exist in `.github/workflows/`

## Basic Usage

### List Available Workflows

```bash
# List all workflows and their jobs
act -l

# List workflows in specific directory
cd beltic-cli
act -l
```

### Run Default Workflow

```bash
# Run default workflow (push event)
act

# Run with specific event
act push
act pull_request
act workflow_dispatch
```

### Run Specific Workflow

```bash
# Run specific workflow file
act -W .github/workflows/ci.yml

# Run with specific event
act push -W .github/workflows/ci.yml
```

### Run Specific Job

```bash
# Run specific job from workflow
act -j test

# Run job from specific workflow
act -j test -W .github/workflows/ci.yml
```

## Advanced Usage

### Dry Run (Validate Syntax)

```bash
# Dry run - don't actually execute
act -n

# Dry run specific workflow
act -n -W .github/workflows/ci.yml
```

### Use Specific Platform

```bash
# Use specific platform image
act -P ubuntu-latest=catthehacker/ubuntu:act-latest

# Use macOS image (for macOS-specific workflows)
act -P macos-latest=catthehacker/ubuntu:act-latest
```

### With Secrets

```bash
# Create .secrets file (add to .gitignore!)
cat > .secrets <<EOF
GITHUB_TOKEN=your_token_here
NPM_TOKEN=your_npm_token_here
PYPI_API_TOKEN=your_pypi_token_here
HOMEBREW_TAP_TOKEN=your_token_here
EOF

# Run with secrets
act --secret-file .secrets

# Run specific workflow with secrets
act -W .github/workflows/release.yml --secret-file .secrets
```

### With Environment Variables

```bash
# Create .env file
cat > .env <<EOF
NODE_VERSION=20.x
PYTHON_VERSION=3.11
EOF

# Run with environment variables
act -e .env
```

### Verbose Output

```bash
# Show verbose output
act -v

# Show very verbose output
act -vv
```

## Repository-Specific Examples

### beltic-cli (Rust)

```bash
cd beltic-cli

# Test CI workflow
act push -W .github/workflows/ci.yml

# Test release workflow (dry run)
act -n -W .github/workflows/release.yml

# Test sync schemas workflow
act workflow_dispatch -W .github/workflows/sync-schemas.yml
```

### beltic-sdk (TypeScript)

```bash
cd beltic-sdk

# Test CI workflow
act push -W .github/workflows/ci.yml

# Test release workflow (requires secrets)
act push -W .github/workflows/release.yml --secret-file .secrets

# Test sync schemas workflow
act workflow_dispatch -W .github/workflows/sync-schemas.yml
```

### fact-python (Python)

```bash
cd fact-python

# Test CI workflow
act push -W .github/workflows/ci.yml

# Test release workflow (requires secrets)
act push -W .github/workflows/release.yml --secret-file .secrets

# Test sync schemas workflow
act workflow_dispatch -W .github/workflows/sync-schemas.yml
```

### beltic-spec (Validation)

```bash
cd beltic-spec

# Test validate workflow
act push -W .github/workflows/validate.yml
```

## Common Issues and Solutions

### Issue: act can't find workflow

**Solution**: Make sure you're in the repository root directory

```bash
cd beltic-cli
act -l
```

### Issue: Docker not running

**Solution**: Start Docker daemon

```bash
# macOS
open -a Docker

# Linux
sudo systemctl start docker
```

### Issue: Platform-specific workflows fail

**Solution**: Use appropriate platform image or skip platform-specific steps

```bash
# Skip macOS-specific steps
act -j test --skip-job build-macos
```

### Issue: Secrets not available

**Solution**: Create `.secrets` file (and add to `.gitignore`)

```bash
echo ".secrets" >> .gitignore
cat > .secrets <<EOF
GITHUB_TOKEN=your_token
EOF
act --secret-file .secrets
```

## Best Practices

1. **Always dry run first**: `act -n` to validate syntax
2. **Test incrementally**: Test one job at a time
3. **Use secrets file**: Keep `.secrets` in `.gitignore`
4. **Test before pushing**: Catch issues locally
5. **Check act version**: Update regularly for latest features

## Notes

- Some workflows may not run perfectly with act (especially release workflows)
- macOS-specific workflows may need special handling
- Secrets are required for workflows that publish or create releases
- Use `act -n` for quick syntax validation

