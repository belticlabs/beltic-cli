# GitHub Actions Workflow Status

## Purpose
Quick overview of which repositories have GitHub Actions workflows set up.

## Current Status

| Repository | CI | Release | Sync Schemas | Notes |
|------------|----|---------|--------------|-------|
| **beltic-cli** | ✅ | ✅ | ✅ | Complete - Rust CI, multi-platform release, schema sync |
| **beltic-sdk** | ✅ | ✅ | ✅ | Complete - TypeScript CI, semantic-release, schema sync + type gen |
| **fact-python** | ✅ | ✅ | ✅ | Complete - Python CI (3.10-3.12), PyPI release, schema sync |
| **beltic-spec** | ✅ | ❌ | ❌ | Has validate workflow (Node + Python validation) |
| **wizard** | ✅ | ✅ | ❌ | Has build, publish, and PR validation workflows |
| **kya-platform** | ❓ | ❓ | ❓ | Check if workflows exist |
| **nasa** | ❓ | ❓ | ❓ | Check if workflows exist |

## Check Workflow Status

```bash
# List all workflow files
find . -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" | grep -v node_modules | sort

# Check specific repository
ls -la beltic-cli/.github/workflows/
ls -la beltic-sdk/.github/workflows/
ls -la fact-python/.github/workflows/
```

## Validate Workflows

Use the `validate-github-actions.md` command to validate workflows.

Use the `test-workflow-with-act.md` command to test workflows locally with `act`.

## Missing Workflows

If workflows are missing:

1. **Check repository type**: Determine if it's Rust, TypeScript, Python, etc.
2. **Copy from similar repo**: Use existing workflow as template
3. **Adapt for repository**: Update paths, commands, dependencies
4. **Test locally**: Use `act` to test before committing
5. **Commit workflow**: Add to `.github/workflows/` directory

## Notes

- All workflows should use latest action versions (v4/v5)
- CI workflows should run on push and pull_request
- Release workflows should trigger on tag push
- Sync schemas workflows should run weekly (schedule) and allow manual trigger

