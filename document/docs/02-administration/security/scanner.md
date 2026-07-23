---
title: Security Scanning
sidebar_position: 4
description: Use Skill Scanner to add automated security checks to the skill publish pipeline
---

# Security Scanning

SkillHub can integrate `skill-scanner` into the publish pipeline to automatically inspect uploaded skill packages and persist the results as security audit records.

## Scan Flow

When scanning is enabled, the publish flow becomes:

1. A user publishes a skill package
2. The backend creates a version and moves it to `SCANNING`
3. The backend enqueues a scan task
4. `skill-scanner` consumes the task and runs analysis
5. The result is stored in `security_audit`
6. The version moves to `PENDING_REVIEW`, or to `SCAN_FAILED` after final retry exhaustion
7. The existing human review workflow continues afterward

## Typical Use Cases

- Add automated risk checks before manual review
- Retain scan results and audit evidence for governance
- Detect suspicious code, leaked secrets, or risky behavior patterns in skill packages

## Runtime Modes

Two modes are supported:

- `local`: the backend passes a filesystem path to the scanner, suitable for shared filesystem setups
- `upload`: the backend uploads the package archive directly, suitable for Docker, Kubernetes, and split deployments

Recommended usage:

- Local development: prefer `local`
- Production, Kubernetes, or split services: prefer `upload`

## Key Configuration

Core backend configuration:

```yaml
skillhub:
  security:
    scanner:
      enabled: false
      base-url: http://localhost:8000
      health-path: /health
      scan-path: /scan-upload
      mode: upload
      connect-timeout-ms: 5000
      read-timeout-ms: 300000
      retry-max-attempts: 3
```

Common environment variables:

- `SKILLHUB_SECURITY_SCANNER_ENABLED`
- `SKILLHUB_SECURITY_SCANNER_URL`
- `SKILLHUB_SECURITY_SCANNER_MODE`
- `SKILLHUB_SCAN_STREAM_KEY`
- `SKILLHUB_SCAN_STREAM_GROUP`

## How To Verify

After enabling scanning, validate it with these steps:

1. Publish a test skill package
2. Confirm the version first moves to `SCANNING`
3. Confirm a `security_audit` record is created
4. Confirm the version eventually moves to `PENDING_REVIEW` or `SCAN_FAILED`
5. Call the security audit API to inspect the result

```text
GET /api/v1/skills/{skillId}/versions/{versionId}/security-audit
```

## Result Fields

Security audit results usually include:

- `scanId`
- `scannerType`
- `verdict`
- `isSafe`
- `maxSeverity`
- `findingsCount`
- `findings`
- `scanDurationSeconds`
- `scannedAt`

## Deployment Recommendations

- Keep scanning disabled at first in local environments, then enable it after the main flow is stable
- Use `upload` mode in Kubernetes to avoid relying on a shared writable filesystem
- In production, keep scan results alongside human review records as governance evidence

## Next Steps

- [Review Workflow](../governance/review-workflow) - Understand the approval flow after scanning
- [Deployment Configuration](../deployment/configuration) - Review deployment-related settings
