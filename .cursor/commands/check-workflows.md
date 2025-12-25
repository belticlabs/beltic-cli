# Check GitHub Actions Workflows

## Purpose
Quickly check which repositories have GitHub Actions workflows and identify any missing or incomplete workflows.

## Process

### 1. List All Workflows

```bash
# Find all workflow files
find . -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" | grep -v node_modules | sort
```

### 2. Check Repository Coverage

Expected workflows by repository:

| Repository | CI | Release | Sync Schemas | Status |
|------------|----|---------|--------------|--------|
| **beltic-cli** | ✅ | ✅ | ✅ | Complete |
| **beltic-sdk** | ✅ | ✅ | ✅ | Complete |
| **fact-python** | ✅ | ✅ | ✅ | Complete |
| **beltic-spec** | ✅ (validate) | ❌ | ❌ | Partial |
| **wizard** | ✅ (build) | ✅ (publish) | ❌ | Partial |
| **kya-platform** | ❓ | ❓ | ❓ | Unknown |
| **nasa** | ❓ | ❓ | ❓ | Unknown |
| **homebrew-tap** | ❓ | ❓ | ❓ | Unknown |

### 3. Validate Workflow Structure

For each workflow file, check:

- [ ] **File naming**: Uses `.yml` or `.yaml` extension
- [ ] **Location**: In `.github/workflows/` directory
- [ ] **Syntax**: Valid YAML
- [ ] **Triggers**: Appropriate `on:` events
- [ ] **Jobs**: At least one job defined
- [ ] **Steps**: Each job has steps

### 4. Check for Required Workflows

#### CI Workflow (Required for all repos)
- [ ] Exists in `.github/workflows/ci.yml`
- [ ] Triggers on `push` and `pull_request`
- [ ] Runs tests
- [ ] Runs linting/formatting checks
- [ ] Builds project

#### Release Workflow (Required for publishable repos)
- [ ] Exists in `.github/workflows/release.yml`
- [ ] Triggers on tag push (`tags: ['v*']`)
- [ ] Builds release artifacts
- [ ] Publishes to package registry (npm, PyPI, etc.)

#### Sync Schemas Workflow (Required for repos using schemas)
- [ ] Exists in `.github/workflows/sync-schemas.yml`
- [ ] Triggers on schedule (weekly) and `workflow_dispatch`
- [ ] Downloads schemas from beltic-spec
- [ ] Creates PR if changes detected

### 5. Quick Validation Commands

```bash
# Check workflow syntax with act
act -l

# Validate specific workflow
act -n -W .github/workflows/ci.yml

# Check for common issues
grep -r "actions/checkout@v[123]" .github/workflows/ || echo "All using v4+"
grep -r "actions/setup-node@v[123]" .github/workflows/ || echo "All using v4+"
grep -r "actions/setup-python@v[1234]" .github/workflows/ || echo "All using v5+"
```

## Missing Workflows

If a repository is missing workflows:

1. **Check repository type**: Rust, TypeScript, Python, etc.
2. **Copy from similar repository**: Use existing workflow as template
3. **Adapt for repository**: Update paths, commands, etc.
4. **Test locally**: Use `act` to test before committing
5. **Add to repository**: Commit workflow file

## Notes

- Use `act` to test workflows locally before pushing
- Keep workflows consistent across similar repositories
- Update action versions regularly
- Add path filters to reduce unnecessary workflow runs

