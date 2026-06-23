# Contributing

## Before you start

Read [DESIGN.md](DESIGN.md). The key design decisions — especially why
`ASUSHOST` excludes colons, why we parse from `message` not `real_message`,
and why `event.dataset` is removed before dispatch — are non-obvious. A
well-intentioned simplification of these parts will reintroduce fixed bugs.

## Reporting issues

Open a GitHub issue with the following information:

- **Security Onion version** (from the SO admin UI or `so-version`)
- **Elasticsearch version** (from `GET /` in Kibana Dev Tools)
- **Router model and firmware version**
- **Which dataset is affected** (`asus.firewall`, `asus.wireless`, etc.)
- **A sanitized example log line** — remove or replace any real IP addresses,
  MAC addresses, or hostnames before posting. A pattern like
  `Jun 10 12:06:18 hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated`
  is ideal — synthetic but structurally accurate.
- **What you expected vs. what you got** — the full simulate output from
  Kibana Dev Tools is helpful here.

> **Never paste real syslog output directly into an issue.** Real log lines
> can contain MAC addresses, hostnames, and network topology information.
> Replace any real values with synthetic placeholders before posting.

## Setting up locally

No dependencies beyond Python 3 (stdlib only):

```bash
git clone https://github.com/scweeks/securityonion-asus-router.git
cd securityonion-asus-router
python3 tests/run_tests.py
```

All 30 tests should pass immediately with no setup.

If you have a real ASUS syslog capture for bulk validation — keep it on your
own machine and never commit it (see [.gitignore](.gitignore)):

```bash
python3 tests/run_tests.py /path/to/your/syslog.txt
```

## Adding support for a new daemon or message shape

1. **Write the test first.** Add one or more representative log lines to
   `tests/run_tests.py` as `check(...)` calls with explicit field assertions.
   The test must fail before your fix and pass after — this confirms you
   actually fixed what you intended.

2. **Determine the right dataset.** Check the dataset taxonomy in README.md
   to decide which sub-pipeline the new daemon belongs in.

3. **Update the dispatcher if needed.** If the new daemon's `process.name`
   isn't already handled, add a dispatch condition to `pipelines/asus`.

4. **Add parsing logic in two places together:**
   - The appropriate JSON sub-pipeline file under `pipelines/`
   - The corresponding Python function in `tests/simulate_v9.py`
   These must stay in sync — a PR that updates one without the other
   will be asked to update the other before merging.

5. **Confirm tests pass:**
   ```bash
   python3 tests/run_tests.py
   ```

6. **Open a PR.** CI re-runs the full test suite automatically. A PR cannot
   be merged while CI is red.

## PR checklist

- [ ] `python3 tests/run_tests.py` passes locally with 0 failures
- [ ] New daemon shapes have a `check(...)` assertion in `run_tests.py`
- [ ] Both the JSON pipeline file and `simulate_v9.py` are updated together
- [ ] No real IP addresses, MAC addresses, or hostnames in any file
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`
- [ ] `DESIGN.md` is updated if a new design decision was made

## What CI checks

On every push and PR to `main`, GitHub Actions:

1. Validates JSON syntax of all six pipeline files
2. Runs the full 30-assertion synthetic test suite

Results are written to the GitHub job summary so you can see exactly which
tests passed or failed without digging through raw logs. A PR cannot be
merged if either check fails.

## Painless script tips

Elasticsearch's Painless scripting language has a few non-obvious restrictions
compared to Java:

- **No `charAt()` comparisons with char literals.** `b.charAt(0) == 'x'`
  causes a compile error (`Cannot cast from [char] to [java.lang.Object]`).
  Use `b.startsWith('x')` instead — functionally identical.
- **String comparison uses `.equals()`, not `==`**, for non-literal comparisons.
- **`splitOnToken()` instead of `split()`** for splitting strings on a single
  character (avoids regex overhead).
- **Always `ignore_failure: true`** on script processors. A runtime exception
  silently drops the entire document in production without it.
- **No comments inside JSON strings.** Painless source lives inside a JSON
  string value — use descriptive variable names instead of inline comments.

The Python simulator (`tests/simulate_v9.py`) avoids all these restrictions
since it runs standard Python, but it is your responsibility to ensure the
corresponding Painless script handles the same logic correctly. When in doubt,
test with `_simulate` in Kibana Dev Tools before opening a PR.

## Data privacy policy

This repository must never contain real network log data. The `.gitignore`
blocks common log file patterns, but it is your responsibility to ensure:

- No real IP addresses from your environment appear in any file
- No real MAC addresses appear in any file
- No real hostnames appear in any file
- No syslog captures, pcaps, or log exports are committed

Use synthetic values in test cases (the existing tests use RFC 5737
documentation addresses) and replace any real values with placeholders
before opening an issue or PR.
