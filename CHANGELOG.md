# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-23

Initial public release. Complete rewrite of the v1–v8 single-file parser into
a six-pipeline architecture matching Security Onion's own platform conventions.

### Fixed

- `process.name` resolving to wireless interface names (e.g. `wl1.2`) instead
  of the actual daemon name for hostapd traffic — root-caused to the upstream
  `syslog` pipeline stripping the header before v1–v8's fallback grok ran on
  the already-stripped remainder. Fixed by parsing the header directly from the
  original `message` field with a custom `ASUSHOST` pattern that excludes
  colons.
- `event.dataset` always landing as `asus.syslog` in production — caused by
  the upstream `syslog` pipeline pre-setting `event.dataset = "syslog"` which
  made all dispatch conditions' `ctx.event?.dataset == null` guards evaluate
  to false. Fixed by removing `event.dataset` at the top of the entry pipeline
  before any dispatch.
- Painless compile error (`Cannot cast from [char] to [java.lang.Object]`) in
  `asus.system`'s crash-dump detection script — fixed by replacing
  `b.charAt(0) == 'x'` with `b.startsWith('x')`.
- `user.name` and `source.ip` not extracted for successful dropbear SSH logins
  — caused by the grok pattern expecting `"<word> auth succeeded for"` when
  the actual Dropbear log format is `"Login succeeded for"`.
- Kernel-sourced wireless driver/firmware messages (`SBF:`, `WLC_SCB_*`,
  `CFG80211-ERROR`, `not mesh client`, `not exist in UDB`) routing to
  `asus.system` instead of `asus.wireless`.

### Changed

- Restructured from one monolithic 58-processor pipeline into six single-purpose
  files: `asus` (entry/dispatcher), `asus.firewall`, `asus.wireless`,
  `asus.dhcp`, `asus.auth`, `asus.system`.
- Removed duplicate re-parsing of the same daemons that had accumulated across
  v3–v8 (hostapd, wlceventd, kernel SBF each parsed 2–4× in v8).
- Removed redundant severity/facility Painless script that duplicated (with
  different label casing) what the upstream `syslog` pipeline already computes.
  Kept an independent computation so the fields are populated correctly even
  when the upstream attempt does not fire (no `<PRI>` prefix in traffic).
- `observer.type` now defaults to `"router"` and is overridden to `"firewall"`
  only by `asus.firewall`, correcting v8's blanket `"firewall"` for all datasets.
- `event.dataset` values are now bare suffixes (`firewall`, not `asus.firewall`)
  per SO convention, relying on the platform's `common` pipeline to concatenate.

### Added

- Python test harness (`tests/simulate_v9.py`, `tests/run_tests.py`) with 30
  assertion-based test cases covering every daemon shape and edge case.
- GitHub Actions workflow validating JSON syntax and running the test suite on
  every push and PR to `main`.
- `DESIGN.md` documenting the root-cause analysis and key design decisions.
