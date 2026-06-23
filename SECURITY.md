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

For anything in scope, open a GitHub issue. If the issue is sensitive enough
that you prefer not to disclose it publicly before a fix is available, contact
the maintainer directly via GitHub private messaging before opening an issue.

Please include:

- A description of the issue and its potential impact
- Steps to reproduce, using only synthetic/sanitized data (no real IPs or MACs)
- Which pipeline file(s) are affected

## Data in this repository

This repository intentionally contains no real network log data. All IP
addresses use RFC 5737 documentation ranges (`192.0.2.x`, `198.51.100.x`,
`203.0.113.x`) which are reserved for examples and will never appear in real
traffic. If you discover real network addresses or other sensitive information
committed to this repository, please report it immediately.
