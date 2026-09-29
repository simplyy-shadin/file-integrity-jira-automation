# Security Policy

## Reporting a vulnerability

Please use GitHub private vulnerability reporting when available rather than
opening a public issue for a security flaw.

Include the affected component, reproduction steps, security impact, and any
relevant logs with credentials or tokens removed.

## Secrets

Never commit:

- `.env`
- `FIM_INTEGRITY_KEY`
- Jira API tokens
- production baseline files
- runtime event databases

If any of those values are accidentally committed, rotate the affected secret
rather than relying only on deleting the Git history.

## Trust boundary

The HMAC integrity key is the root of trust for baseline signatures and the
tamper-evident event chain. It should be stored separately from the monitored
directory and protected with operating-system or secret-management controls.

This repository is an educational security-engineering implementation, not a
replacement for enterprise endpoint detection, host attestation, or a hardened
remote logging service.
