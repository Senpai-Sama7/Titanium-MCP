# SECURITY and Hardening Checklist for Titanium Repo Operator

This document outlines the recommended security posture for deploying the Titanium MCP server in production.

## Secrets
- Do not store secrets in repository or images.
- Use Vault or cloud KMS (AWS Secrets Manager, GCP Secret Manager, Azure KeyVault).
- Inject secrets at runtime via environment variables or mounted files from the orchestrator (Kubernetes Secrets, HashiCorp Vault CSI).

## Least privilege
- Run the container under a non-root user.
- Mount only needed paths; workspace should be a dedicated volume.
- Restrict network egress; use an allowlist/proxy for required API calls.
- Use short-lived tokens and rotate them frequently.

## Git Permissions
- Use service accounts with minimal repo permissions (create branch, push to specific refs if needed).
- Prefer PR creation flow over direct push/merge for production workflows.
- For production autonomy, require branch policies and human approvals before merging to protected branches.

## Audit & Monitoring
- Store append-only audit logs to a tamper-evident storage (S3 with immutability or cloud logging).
- Send metrics to Prometheus + traces to a tracing collector (OTEL).
- Configure alerting for abnormal behavior (high rate of patches, repeated failures).

## Runtime sandboxing
- Run MCP server in a container with limited capabilities (no SYS_ADMIN, no privilege escalation).
- Use seccomp and AppArmor profiles where available.
- Set CPU/memory quotas.
- Consider running agent operations in ephemeral containers created per worktree.

## Operational controls
- Maintain maximum LOC per iteration and max iterations per task budgets.
- Provide human approval gates for high-risk operations (e.g., direct prod push).
- Maintain kill-switch that disables auto-commit/mutation abilities instantly.

## Incident response
- Rotate service tokens on suspicious activity.
- Revoke MCP registrations in Claude Code when compromised.
- Keep nightly backups of critical repos and audit logs.
