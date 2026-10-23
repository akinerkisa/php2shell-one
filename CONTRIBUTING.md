# Contributing

1. Open an issue explaining the user scenario, evidence sources and platform.
2. PRs must include offline tests and false-positive/false-assurance cases.
3. For a new vendor threshold, include an official first-party advisory and a sample patched/unpatched package pair. No assumptions from upstream PHP_VERSION.
4. For a detection, include benign fixtures, explicit detection limitations and data minimization.
5. Run `python -m unittest discover -s tests -v` and `python -m compileall -q src`.
6. Do not submit exploit payloads, working RCE samples, private incident logs, stolen data or executable malware.
7. Prefer small, reviewable changes. Defensive code must not execute untrusted shell strings.

See [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).
