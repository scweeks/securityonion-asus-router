# Security Policy

## Scope

This repository contains Elasticsearch ingest pipeline configuration files and
a Python test harness. It does not contain a running service, web application,
or executable binary. The attack surface is limited, but the following are in
scope for security reports:

- A parsing bug that causes a category of malicious traffic to be silently
  misclassified (e.g. dropped into `asus.syslog` instead of `asus.firewall`),
  reducing detection coverage without the operator knowing
- A grok pattern or Painless script that could be exploited via crafted syslog
  input to cause unexpected behavior in Elasticsearch (e.g. unintended field
  injection, excessive resource consumption)
- Sensitive data (real IP addresses, MACs, hostnames) inadvertently committed
  to this repository

## Out of scope

- Vulnerabilities in Security Onion, Elasticsearch, or Kibana themselves —
  report those to the respective projects
- Vulnerabilities in ASUS router firmware — report those to ASUS
- General pipeline gaps (missing daemons, incomplete field extraction) — open
  a regular issue

## Reporting

**For exploitable parser bypasses or any issue you prefer to disclose
privately**, use GitHub's private vulnerability reporting:

👉 [Report a vulnerability](../../security/advisories/new)

This ensures the report is visible only to the maintainer until a fix is
published. Do not open a public issue for exploitable issues.

For non-exploitable issues (documentation gaps, missing daemon support,
general feedback), open a regular GitHub issue.

Please include in your report:

- A description of the issue and its potential impact
- Steps to reproduce, using only synthetic/sanitized data (no real IPs or MACs)
- Which pipeline file(s) are affected

### Response expectations

| Severity | Initial response | Target fix |
|---|---|---|
| High (parsing bypass, data exposure) | 48 hours | 7 days |
| Medium (detection gap, silent failure) | 5 days | 30 days |
| Low (documentation, cosmetic) | 14 days | Next release |

Confirmed vulnerabilities will be addressed via a GitHub Security Advisory
before public disclosure.

## Known transport limitation

ASUS stock firmware sends syslog over unauthenticated UDP (port 514). This is
a protocol limitation, not a parser defect. See the Security Considerations
section of README.md for network-layer mitigations.

## Data in this repository

This repository intentionally contains no real network log data. All IP
addresses use RFC 5737 documentation ranges (`192.0.2.x`, `198.51.100.x`,
`203.0.113.x`) which are reserved for examples and will never appear in real
traffic. If you discover real network addresses or other sensitive information
committed to this repository, please report it immediately using the private
vulnerability reporting link above.
