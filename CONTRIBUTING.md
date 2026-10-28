# Contributing

- Python 3.11+, pytest. Install with `pip install -e ".[dev]"`, run `python -m pytest -q`.
- Every new check needs: a test with a flagged example, a test with a
  safe example that is *not* flagged, and a README catalogue entry with an
  attack story.
- Do not add a check that fails the gate on medium/low confidence by
  default. If a check is heuristic, keep it advisory and say so.
- Do not add payloads that target a real third-party system, and do not
  submit scanner output about someone else's repo as a security report
  without their permission. Scan your own repos, or repos you are
  authorised to review.
- Keep the scanner offline and dependency-light. No network calls in checks.
