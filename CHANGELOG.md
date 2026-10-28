# Changelog

## 0.1.0 — 2026-10-29
- Initial release: Python-only static scanner (library + CLI).
- Checks: SHELL001, TOOL001, TOOL002, FILE001, SECRET001, SECRET002, AGENT001.
- CI gate: high severity + high confidence by default, suppression file, SARIF output.
- Adversarial pack (stub agent only) with direct + indirect injection cases.
- Examples: deliberately vulnerable vs fixed agent code.
- Docs: quickstart, check catalogue with attack stories, CI guide.
- Deliberately out of v1: non-Python languages, hosted dashboard, LLM-as-judge,
  deep red-teaming (see garak / Promptfoo for that), and a `.github/workflows/`
  file in the initial push (see docs/ci-workflow-example.yml instead).
