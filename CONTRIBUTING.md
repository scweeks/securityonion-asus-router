# Contributing

## Before you start

Read [DESIGN.md](DESIGN.md). The key design decisions — especially why
`ASUSHOST` excludes colons, why we parse from `message` not `real_message`,
and why `event.dataset` is removed before dispatch — are non-obvious. A
well-intentioned simplification of these parts will reintroduce fixed bugs.

## Running the tests

No external dependencies required beyond Python 3.

```bash
python3 tests/run_tests.py
```

All 30 assertions must pass before opening a PR. The CI enforces this.

If you have a real ASUS syslog capture (not required but strongly encouraged):

```bash
python3 tests/run_tests.py /path/to/syslog.txt
```

The bulk validation checks that zero lines produce no `event.dataset` and zero
lines end up with a wireless interface name in `process.name`.

## Adding support for a new daemon or message shape

1. Add one or more representative real log lines to `tests/run_tests.py` as
   `check(...)` calls with explicit field assertions. Do this first, before
   writing any pipeline code, so the new test fails before your fix and passes
   after — confirming you actually fixed what you intended.

2. Determine which sub-pipeline the new daemon belongs in based on the dataset
   taxonomy in README.md.

3. Add the dispatch condition to `pipelines/asus` if needed (new `process.name`
   value not already covered by an existing condition).

4. Add the parsing logic to the appropriate sub-pipeline JSON file and mirror
   it in the corresponding function in `tests/simulate_v9.py`.

5. Confirm `python3 tests/run_tests.py` passes with zero failures.

6. Open a PR. The CI will re-run the test suite automatically.

## PR checklist

- [ ] `python3 tests/run_tests.py` passes locally with 0 failures
- [ ] New daemon shapes have a `check(...)` test case in `run_tests.py`
- [ ] Both the JSON pipeline file and `simulate_v9.py` are updated together
- [ ] CHANGELOG.md has an entry under `[Unreleased]`
- [ ] DESIGN.md is updated if a new design decision was made

## What CI checks

On every push and PR to `main`, GitHub Actions:

1. Validates JSON syntax of all six pipeline files
2. Runs the full synthetic test suite (`tests/run_tests.py`)

A PR cannot be merged if either check fails.

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
  in a script silently drops the entire document in production without this.

The Python simulator (`simulate_v9.py`) avoids all these issues since it runs
standard Python, but it is your responsibility to make sure the corresponding
Painless script handles the same logic correctly.
