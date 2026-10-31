# Security Policy

## Supported Versions

Only the latest released version receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.15.x  | :white_check_mark: |
| < 0.15  | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within SoliTools, please do **not** open a public issue. Publicly disclosing a flaw can put other users at risk before a fix is available.

Instead, please report vulnerabilities via one of the following methods:

1. **GitHub Private Vulnerability Reporting**: Submit a private advisory directly through GitHub on the [Security Advisories](https://github.com/soliofski/SoliTools/security/advisories) page.
2. **Email**: Contact the maintainer directly at `Soliofski@users.noreply.github.com`.

### What to Include in Your Report

Please provide as much information as possible to help us reproduce and resolve the issue quickly:
- Type of vulnerability (e.g., SSRF bypass, unsafe handling of untrusted input, buffer overflow).
- Clear, step-by-step reproduction steps or a minimal proof of concept (PoC).
- Expected behavior versus actual behavior.
- Any suggested mitigations or patches, if available.

### Response Timeline

- **Initial Acknowledgment**: Within 48 hours.
- **Triage & Status Update**: Within 5 business days with an assessment and planned timeline for resolution.
- **Coordinated Disclosure**: We aim to release a patch and publish a security advisory within 30 days of initial triage.
