# GitLab CI Pipeline Documentation

- File: `samples/gitlab/.gitlab-ci.yml`

## Key pipeline concepts
- **stages**: Defines pipeline phases executed in order (build -> test -> security -> deploy).
- **rules**: Controls when jobs run (branch, tag, MR, changes).
- **artifacts**: Files passed between jobs (build outputs, reports).
- **cache**: Speeds up builds by caching dependencies.
- **environment**: Deployment targets with optional URLs and review apps.

## Stages
- `build`
- `test`
- `security`
- `deploy`

## Jobs

### Stage: `security`

#### `iac_security_scan`
- Uses rules: No
- Publishes artifacts: Yes

**Script**
```bash
apk add --no-cache curl bash
echo "Run tfsec/checkov here for Terraform scanning"
echo "Run gitleaks here to detect secrets"
