# False-positive measurement note (local only, aggregate only)

Measured 2026-10-29 by scanning the sibling project in the same workspace
(`prompt-eval-harness`: a Python library/CLI, scanned locally from disk).
No third-party system was probed, and no repo other than the two local
example projects in this repository was scanned.

- Sibling codebase scanned: 26 files, 0 findings, exit 0 (gate passed).
- Vulnerable example (`examples/vulnerable`): 2 files, 7 findings, exit 1
  (gate failed on high severity + high confidence findings).
- Fixed example (`examples/fixed`): 1 file, 0 findings, exit 0.

Interpretation, honestly: this is a tiny, local sample, not a benchmark.
It shows the gate stays quiet on one benign Python codebase and fires on
the deliberately vulnerable example. It does **not** prove a general
false-positive rate, and a clean scan is not proof that code is safe.
Do not quote a single accuracy number from this note.
