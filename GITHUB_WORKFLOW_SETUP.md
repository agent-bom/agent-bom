# GitHub Actions Workflow Setup

## Why wasn't the workflow pushed automatically?

GitHub requires the `workflow` scope to create or update workflow files (`.github/workflows/*.yml`) via API/CLI for security reasons. The current authentication doesn't have this scope.

## How to add the workflow

You have **three options**:

---

### Option 1: Add via GitHub Web Interface (Easiest)

1. Go to your repository: https://github.com/agent-bom/agent-bom

2. Click "Add file" → "Create new file"

3. Name it: `.github/workflows/security-scan.yml`

4. Copy and paste the content from the local file:
   ```bash
   cat .github/workflows/security-scan.yml
   ```

5. Commit directly to `main` branch

**Done!** The workflow will run automatically on:
- Push to `main` or `develop`
- Pull requests
- Daily at 2 AM UTC
- Manual trigger via "Actions" tab

---

### Option 2: Re-authenticate with Workflow Scope

```bash
# Re-authenticate with workflow scope
gh auth login --scopes workflow

# Stage and push the workflow
git add .github/workflows/security-scan.yml
git commit -m "Add GitHub Actions security scan workflow"
git push origin main
```

---

### Option 3: Push Manually After Authentication

The workflow file already exists locally at:
```
.github/workflows/security-scan.yml
```

When you're ready:
```bash
git add .github/workflows/security-scan.yml
git commit -m "Add CI/CD workflow for automated security scanning"
git push origin main
```

---

## What the workflow does

The `security-scan.yml` workflow provides:

### 🔍 Automated Testing
- **Linting**: Runs `ruff` and `mypy` on every commit
- **Unit tests**: Runs `pytest` across Python 3.10, 3.11, 3.12
- **Coverage**: Uploads coverage reports to Codecov

### 🐕 Self-Scanning (Dogfooding)
- Runs `agent-bom scan --enrich` on the agent-bom project itself
- Fails if critical vulnerabilities (risk score ≥ 9.0) are found
- Uploads AI-BOM report as artifact

### 🐳 Docker Build
- Builds Docker image on every push
- Publishes to GitHub Container Registry (ghcr.io)
- Tags with:
  - Branch name (e.g., `main`, `develop`)
  - PR number (e.g., `pr-123`)
  - Git SHA (e.g., `sha-abc1234`)
  - Semantic version tags (e.g., `v0.3.0`, `0.3`)

### 🧪 Integration Tests
- Runs end-to-end test suite (`test_e2e.sh`)
- Validates OSV.dev connectivity
- Tests package extraction accuracy

### 🔐 Security Audit
- Runs Snyk to check for vulnerabilities in dependencies
- Continues even if issues found (non-blocking)

### 📦 PyPI Release
- Automatically publishes to PyPI when you push a git tag like `v0.3.0`
- Requires `PYPI_TOKEN` secret to be configured

---

## Required Secrets

To enable all workflow features, add these secrets to your repository:

### GitHub Settings → Secrets and variables → Actions → New repository secret

| Secret Name | Description | Required? |
|-------------|-------------|-----------|
| `NVD_API_KEY` | NVD API key for enrichment | Optional (but recommended) |
| `PYPI_TOKEN` | PyPI API token for publishing | Required for releases |
| `SNYK_TOKEN` | Snyk API token for security audit | Optional |

**Get NVD API key**: https://nvd.nist.gov/developers/request-an-api-key
**Get PyPI token**: https://pypi.org/manage/account/token/
**Get Snyk token**: https://app.snyk.io/account (free tier available)

---

## Manual Workflow Trigger

Once the workflow is added, you can trigger it manually:

1. Go to: https://github.com/agent-bom/agent-bom/actions
2. Select "Security Scan" workflow
3. Click "Run workflow"
4. Choose branch and options
5. Click "Run workflow" button

---

## Testing the Workflow Locally

You can test the workflow logic locally using `act`:

```bash
# Install act (GitHub Actions local runner)
brew install act  # macOS
# or: curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run workflow locally
act push

# Run specific job
act -j test

# Run with secrets
act -s NVD_API_KEY=your-key-here
```

---

## What's Next?

After adding the workflow:

1. **Add NVD API key** to GitHub Secrets
2. **Watch the first run** in the Actions tab
3. **Fix any failing tests** (if applicable)
4. **Set up branch protection** to require workflow passing before merge
5. **Add status badge** to README:
   ```markdown
   ![Security Scan](https://github.com/agent-bom/agent-bom/actions/workflows/security-scan.yml/badge.svg)
   ```

---

**Questions?** Check the [GitHub Actions documentation](https://docs.github.com/en/actions)
